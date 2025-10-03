import os
import csv
import secrets
import time
import traceback # Importação adicionada para logs de erro mais detalhados
from io import StringIO, BytesIO
from fpdf import FPDF
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging
import re # Importação necessária para a função clean_text aprimorada
import psycopg2 
from psycopg2 import sql 
from psycopg2 import extras 
from psycopg2 import errors as pg_errors 

# --- Configuração da Aplicação ---
DATABASE_URL = os.environ.get("DATABASE_URL")
ALLOWED_DOMAIN = "@vmis.com.br"
ADMIN_EMAIL = "maicon.ferreira@vmis.com.br"
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "chave_fallback_insegura_nao_usar")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["ALLOWED_DOMAIN"] = ALLOWED_DOMAIN
app.config["ADMIN_EMAIL"] = ADMIN_EMAIL
app.config["DATABASE_URL"] = DATABASE_URL

# Configuração de Log para console
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

SERVICOS = [
    "IMAGESERVICE", "DETECTORAPI", "CALIBRATIONAPI", "FILEMANAGERAPI",
    "MCBCOMMUNICATIONAPI", "DETECTORCOMMUNICATION", "USERAPI", "SETTINGSAPI",
    "PERIPHERALSAPI", "CONVEYORBELTAPI", "REPORTAPI", "INSPECTIONAPI",
    "GENERATORAPI", "RABBTIMQ", "LOGSTASH", "MONGO-EXPRESS"
]

# --- FUNÇÃO AUXILIAR DE TEXTO PARA PDF (APRIMORADA) ---
def clean_text(text):
    """
    Remove caracteres não-ASCII e formatação HTML que causam erros de 
    codificação ou de largura (Not enough horizontal space) no FPDF.
    Usa 'latin-1' com substituição para máxima compatibilidade.
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Remove HTML tags simples (e.g., <br>)
    text = re.sub('<[^<]+?>', '', text)
    
    # Substitui caracteres especiais por equivalentes simples (ignora case)
    text = text.replace('ç', 'c').replace('Ç', 'C')
    text = re.sub(r'[áàãâä]', 'a', text, flags=re.IGNORECASE)
    text = re.sub(r'[éèêë]', 'e', text, flags=re.IGNORECASE)
    text = re.sub(r'[íìîï]', 'i', text, flags=re.IGNORECASE)
    text = re.sub(r'[óòõôö]', 'o', text, flags=re.IGNORECASE)
    text = re.sub(r'[úùûü]', 'u', text, flags=re.IGNORECASE)
    
    # Remove ou substitui outros caracteres problemáticos
    text = text.replace('º', '').replace('ª', '')
    text = text.replace('—', '-').replace('–', '-') # Tratamento para travessões
    
    # Garante que seja ASCII compatível com FPDF latin-1
    return text.encode('latin-1', 'replace').decode('latin-1')

# --- Banco de Dados: Funções e Context Manager (POSTGRESQL) ---
# (Funções de DB omitidas por brevidade, pois não foram alteradas)
def get_db_connection():
    if not app.config["DATABASE_URL"]:
        app.logger.error("ERRO CRÍTICO: Variável DATABASE_URL não foi encontrada. Conexão PostgreSQL falhou.")
        raise Exception("DATABASE_URL ausente.")
    
    try:
        conn = psycopg2.connect(app.config["DATABASE_URL"])
        conn.cursor_factory = psycopg2.extras.DictCursor 
        return conn
    except psycopg2.OperationalError as e:
        app.logger.error(f"ERRO CRÍTICO: Falha ao conectar ao PostgreSQL. Detalhes: {e}")
        raise 
    except Exception as e:
        app.logger.error(f"ERRO INESPERADO ao obter conexão com o PostgreSQL: {e}")
        raise

def init_db():
    app.logger.info("--- INICIANDO VERIFICAÇÃO/CRIAÇÃO DE TABELAS (POSTGRESQL) ---")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS erros (
                        id SERIAL PRIMARY KEY,
                        erro TEXT NOT NULL,
                        servico TEXT NOT NULL,
                        solucao TEXT NOT NULL,
                        criado_por TEXT NOT NULL DEFAULT 'desconhecido'
                    )
                """)
                cur.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                                       WHERE table_name='erros' AND column_name='criado_por') THEN
                            ALTER TABLE erros ADD COLUMN criado_por TEXT NOT NULL DEFAULT 'desconhecido';
                        END IF;
                    END
                    $$;
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        id SERIAL PRIMARY KEY,
                        user_email TEXT NOT NULL,
                        token TEXT UNIQUE NOT NULL,
                        expiration_time BIGINT NOT NULL 
                    )
                """)
            conn.commit()
        app.logger.info("✅ SUCESSO: Banco de dados PostgreSQL inicializado e tabelas verificadas/criadas.")
    except Exception as e:
        app.logger.error(f"❌ FALHA: A inicialização do DB foi interrompida. Erro: {e}")
        # Passar aqui é crucial para não travar o aplicativo se o DB falhar na inicialização
        pass 

def check_duplicate_erro(erro, servico, solucao):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id FROM erros 
                    WHERE erro = %s AND servico = %s AND solucao = %s
                """, (erro, servico, solucao))
                return cur.fetchone() is not None 
    except Exception as e:
        app.logger.error(f"Erro ao verificar duplicidade: {e}")
        return False 

def fetch_all_erros():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, erro, servico, solucao, criado_por FROM erros ORDER BY id DESC")
                return [dict(row) for row in cur.fetchall()] 
    except Exception as e:
        app.logger.error(f"Erro ao buscar erros: {e}")
        return []

def insert_erro(erro, servico, solucao, criado_por):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO erros (erro, servico, solucao, criado_por) VALUES (%s, %s, %s, %s)",
                    (erro, servico, solucao, criado_por)
                )
            conn.commit()
            return True
    except pg_errors.UniqueViolation:
        return False
    except Exception as e:
        app.logger.error(f"Erro ao inserir erro: {e}")
        return False

def update_erro(id_, erro, servico, solucao):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE erros SET erro=%s, servico=%s, solucao=%s WHERE id=%s", 
                    (erro, servico, solucao, id_)
                )
            conn.commit()
            return cur.rowcount > 0
    except Exception as e:
        app.logger.error(f"Erro ao atualizar erro: {e}")
        return False

def delete_erro(id_):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM erros WHERE id=%s", (id_,))
            conn.commit()
            return cur.rowcount > 0
    except Exception as e:
        app.logger.error(f"Erro ao deletar erro: {e}")
        return False

def insert_user(email, password_hash):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (email, password_hash) VALUES (%s, %s)", 
                    (email, password_hash)
                )
            conn.commit()
            return True
    except pg_errors.UniqueViolation:
        return False
    except Exception as e:
        app.logger.error(f"Erro ao inserir usuário: {e}")
        return False

def fetch_user_by_email(email):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, password_hash FROM users WHERE email = %s", (email,))
                row = cur.fetchone()
                return dict(row) if row else None 
    except Exception as e:
        app.logger.error(f"Erro ao buscar usuário: {e}")
        return None

def create_reset_token(email):
    try:
        token = secrets.token_hex(32)
        expiration_time = int(time.time()) + 7200
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM password_reset_tokens WHERE user_email = %s", (email,))
                cur.execute(
                    "INSERT INTO password_reset_tokens (user_email, token, expiration_time) VALUES (%s, %s, %s)", 
                    (email, token, expiration_time)
                )
            conn.commit()
            return token
    except Exception as e:
        app.logger.error(f"Erro ao criar token: {e}")
        return None

def get_token_info(token):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT user_email, expiration_time FROM password_reset_tokens WHERE token = %s", (token,))
                row = cur.fetchone()
                if row and row["expiration_time"] > int(time.time()):
                    return row["user_email"]
                return None
    except Exception as e:
        app.logger.error(f"Erro ao buscar token: {e}")
        return None

def delete_reset_token(token):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
            conn.commit()
    except Exception as e:
        app.logger.error(f"Erro ao deletar token: {e}")

def update_user_password(email, new_password_hash):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (new_password_hash, email))
            conn.commit()
            return cur.rowcount > 0
    except Exception as e:
        app.logger.error(f"Erro ao atualizar senha: {e}")
        return False

def is_valid_email(email):
    return email and email.strip().lower().endswith(app.config["ALLOWED_DOMAIN"])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Você precisa fazer login para acessar esta página.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Por favor, preencha o e-mail e a senha.', 'danger')
            return render_template('register.html')
        
        if not is_valid_email(email):
            flash(f"O e-mail deve pertencer ao domínio {app.config['ALLOWED_DOMAIN']}.", 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        if insert_user(email, hashed_password):
            flash('✅ Cadastro realizado com sucesso! Faça seu login.', 'success')
            return redirect(url_for('login')) 
        else:
            flash('❌ Este e-mail já está cadastrado. Tente outro ou faça login.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session:
        session.pop("is_admin", None)
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password") 

        if not email or not password:
            flash("Por favor, insira o e-mail e a senha.", "danger")
            return render_template("login.html")
            
        user_row = fetch_user_by_email(email)
        
        if user_row:
            if check_password_hash(user_row["password_hash"], password):
                if is_valid_email(email):
                    session["user"] = email
                    session["is_admin"] = False 
                    flash(f"Bem-vindo(a), {email.split('@')[0]}!", "success")
                    return redirect(url_for("dashboard"))
                else:
                    flash(f"Acesso negado. O domínio {app.config['ALLOWED_DOMAIN']} é obrigatório.", "danger")
            else:
                flash("Senha incorreta.", "danger")
        else:
            flash("E-mail não encontrado. Considere cadastrar-se.", "danger")
            
    return render_template("login.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password") 
        
        user_row = fetch_user_by_email(email)
        
        if user_row and check_password_hash(user_row["password_hash"], password) and is_valid_email(email):
            if email.lower() == app.config["ADMIN_EMAIL"]:
                session["user"] = email
                session["is_admin"] = True
                flash("ADMINISTRADOR: Acesso total concedido.", "warning")
                return redirect(url_for("dashboard"))
            else:
                flash(f"Acesso negado. Apenas o e-mail {app.config['ADMIN_EMAIL']} pode usar esta rota.", "danger")
        elif user_row:
             flash("Senha incorreta ou domínio inválido.", "danger")
        else:
             flash("E-mail não encontrado.", "danger")
            
    return render_template("admin_login.html", admin_email=app.config["ADMIN_EMAIL"])

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("is_admin", None)
    flash("Você foi desconectado com sucesso.", "info")
    return redirect(url_for("login"))

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if fetch_user_by_email(email):
            token = create_reset_token(email)
            if token:
                reset_link = url_for('reset_password', token=token, _external=True)
                app.logger.info("-" * 50)
                app.logger.info(f"SIMULAÇÃO DE E-MAIL para {email}:")
                app.logger.info(f"CLIQUE AQUI PARA REDEFINIR SENHA: {reset_link}")
                app.logger.info("-" * 50)
                flash('Se o seu e-mail estiver no sistema, um link será gerado (ver logs do servidor).', 'info')
        else:
            flash('Se o seu e-mail estiver no sistema, um link será gerado (ver logs do servidor).', 'info')
        
        return redirect(url_for('login'))
        
    return render_template('password_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email_to_reset = get_token_info(token)
    
    if not email_to_reset:
        flash("Link de redefinição inválido ou expirado.", "danger")
        return redirect(url_for('password_reset'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("As senhas não coincidem.", "danger")
            return render_template('reset_password.html', token=token)
            
        if len(password) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.", "danger")
            return render_template('reset_password.html', token=token)

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        if update_user_password(email_to_reset, hashed_password):
            delete_reset_token(token)
            flash('✅ Senha redefinida com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Erro ao redefinir a senha. Tente novamente.', 'danger')

    return render_template('reset_password.html', token=token)

@app.route("/dashboard", methods=["GET", "POST"])
@login_required 
def dashboard():
    is_admin = session.get("is_admin", False)

    if request.method == "POST":
        action = request.form.get("action")
        
        def get_validated_data(is_update=False):
            data = {
                "erro": request.form.get("erro", "").strip(),
                "servico": request.form.get("servico", "").strip(),
                "solucao": request.form.get("solucao", "").strip()
            }
            if is_update:
                id_str = request.form.get("id", "")
                try: data["id"] = int(id_str)
                except (ValueError, TypeError): data["id"] = None
            
            if not all(k in data and data[k] for k in ["erro", "servico", "solucao"]) or (is_update and data.get("id") is None):
                flash("Preencha todos os campos obrigatórios.", "warning")
                return None
            return data

        if action == "cadastrar":
            data = get_validated_data()
            if data:
                if check_duplicate_erro(data["erro"], data["servico"], data["solucao"]):
                    flash("⚠️ Este erro já foi cadastrado com este serviço e solução.", "warning")
                elif insert_erro(data["erro"], data["servico"], data["solucao"], session['user']):
                    flash("✅ Erro cadastrado com sucesso!", "success")
                else:
                    flash("Erro ao cadastrar. Tente novamente.", "danger")
                
        elif action == "alterar":
            data = get_validated_data(is_update=True)
            if data and data["id"] is not None and update_erro(data["id"], data["erro"], data["servico"], data["solucao"]):
                flash("Erro atualizado!", "success")
            elif data:
                flash("Erro ao atualizar ou ID inválido.", "danger")
                
        elif action == "apagar":
            if not is_admin:
                flash("Permissão negada. Apenas administradores podem apagar.", "danger")
                return redirect(url_for("dashboard"))
                
            id_str = request.form.get("id")
            id_to_delete = None
            try: id_to_delete = int(id_str)
            except (ValueError, TypeError): pass
            
            if id_to_delete is not None and delete_erro(id_to_delete):
                flash("Erro apagado!", "success")
            else:
                flash("Erro ao apagar ou ID inválido.", "danger")
        
        return redirect(url_for("dashboard"))

    erros = fetch_all_erros()
    return render_template("dashboard.html", 
                           erros=erros, 
                           servicos=SERVICOS, 
                           user=session["user"], 
                           is_admin=is_admin)

@app.route("/export/csv")
@login_required
def export_csv():
    erros = fetch_all_erros()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID", "Erro", "Serviço", "Solução", "Criado por"])
    writer.writerows([[r["id"], r["erro"], r["servico"], r["solucao"], r["criado_por"]] for r in erros])
    output = si.getvalue().encode('utf-8')
    
    return send_file(
        BytesIO(output), 
        mimetype="text/csv", 
        as_attachment=True, 
        download_name="erros_cadastrados.csv"
    )

@app.route("/export/pdf")
@login_required
def export_pdf():
    """
    Exporta todos os erros para um arquivo PDF usando FPDF.
    A estrutura de células foi corrigida para garantir o espaço horizontal.
    """
    erros = fetch_all_erros()
    
    try:
        pdf = FPDF()
        # Constante de altura de linha. 6mm é um bom espaçamento.
        LINE_HEIGHT = 6
        LABEL_WIDTH = 20 # Largura fixa para rótulos (e.g., "Erro:", "Solução:")
        
        pdf.set_auto_page_break(auto=True, margin=15) # Margem de 15mm
        pdf.add_page()
        
        # Título do Relatório
        pdf.set_font("Arial", "B", 18) 
        pdf.cell(0, 10, clean_text("Relatório de Erros Cadastrados"), ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 5, clean_text(f"Gerado por: {session.get('user', 'Desconhecido')}"), ln=True, align="C")
        pdf.ln(5)
        
        # Loop principal de geração dos erros
        for r in erros:
            # Garante que sempre haja espaço para o bloco (3 linhas + espaço)
            if pdf.get_y() > 270: 
                pdf.add_page()
            
            # 1. Cabeçalho do Erro: ID + Serviço + Criador
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(0, 0, 0) # Texto preto para contraste no cabeçalho
            pdf.set_font('Arial', 'B', 11)
            # Imprime o cabeçalho do erro em uma linha preenchida
            pdf.cell(0, LINE_HEIGHT, 
                     clean_text(f"ID: {r['id']} | Serviço: {r['servico']} | Criado por: {r['criado_por'].split('@')[0]}"), 
                     1, 1, 'L', True) # 1: border, 1: next line, L: align, True: fill
            
            pdf.set_text_color(0, 0, 0) # Volta ao texto padrão (preto)
            pdf.set_font('Arial', '', 10) # Fonte padrão para o corpo
            pdf.ln(1)
            
            # 2. Descrição do Erro (Multi-line)
            # Rótulo em negrito
            pdf.set_font('Arial', 'B', 10)
            pdf.set_x(pdf.l_margin) # Volta para a margem esquerda (CRÍTICO)
            pdf.cell(LABEL_WIDTH, LINE_HEIGHT, "Erro:", 0, 0, 'L')
            
            # Conteúdo (w=0 usa o espaço restante da linha)
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, LINE_HEIGHT, clean_text(r['erro']), 0, 'L') # multi_cell(0, ...) garante quebra de linha

            # 3. Solução (Multi-line)
            # Rótulo em negrito
            pdf.set_font('Arial', 'B', 10)
            pdf.set_x(pdf.l_margin) # Volta para a margem esquerda (CRÍTICO)
            pdf.cell(LABEL_WIDTH, LINE_HEIGHT, "Solução:", 0, 0, 'L')
            
            # Conteúdo (w=0 usa o espaço restante da linha)
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, LINE_HEIGHT, clean_text(r['solucao']), 0, 'L')

            # 4. Separador
            pdf.ln(1)
            pdf.set_draw_color(150, 150, 150)
            # Desenha uma linha de ponta a ponta
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(2) # Espaço após o separador

        # O método pdf.output(dest='S') retorna o conteúdo em bytes.
        pdf_output = pdf.output(dest='S')
        
        return send_file(
            BytesIO(pdf_output),
            mimetype="application/pdf", 
            as_attachment=True, 
            download_name="erros_cadastrados.pdf"
        )
    except Exception as e:
        app.logger.error(f"ERRO CRÍTICO na geração do PDF: {e}")
        app.logger.error(traceback.format_exc()) 
        flash("❌ Erro ao gerar o PDF. Verifique se o conteúdo dos erros não contém caracteres muito incomuns (como emojis).", "danger")
        return redirect(url_for("dashboard"))


def setup_application(app):
    with app.app_context():
        init_db()

setup_application(app)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
