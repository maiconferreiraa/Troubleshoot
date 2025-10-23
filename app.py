import os
import csv
import secrets
import time
import traceback
from io import StringIO, BytesIO
from fpdf import FPDF
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging
import re
import psycopg2 
from psycopg2 import sql 
from psycopg2 import extras 
from psycopg2 import errors as pg_errors 
import pandas as pd  # Importação para ler o .xlsx

# --- Configuração da Aplicação ---
DATABASE_URL = os.environ.get("DATABASE_URL")
#DATABASE_URL = "postgresql://vmis_db_user:8TDeUr6zcACsxeRbpKj0dO5ttJW9tDCk@dpg-d3fa0n6uk2gs73dcqv9g-a.oregon-postgres.render.com/vmis_db"
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

# --- FUNÇÃO PARA CARREGAR E-MAILS AUTORIZADOS ---
def load_authorized_emails():
    """Carrega emails autorizados do users.xlsx na inicialização."""
    filepath = os.path.join(app.root_path, "users.xlsx")
    app.logger.info(f"Tentando carregar lista de e-mails de {filepath}...")
    
    if not os.path.exists(filepath):
        app.logger.warning(f"AVISO: Arquivo 'users.xlsx' não encontrado na raiz. Nenhum e-mail será autorizado para cadastro.")
        return set()
        
    try:
        # Lê o Excel, assumindo que a primeira linha é o cabeçalho
        df = pd.read_excel(filepath) 
        
        # Verifica se a coluna "User principal name" (Coluna C) existe
        if "User principal name" not in df.columns:
            app.logger.error(f"Erro: Coluna 'User principal name' não encontrada em {filepath}. Verifique o nome da coluna.")
            return set()
            
        # Pega a coluna, remove valores nulos (NaN), converte para string, e depois minúsculo
        email_list = df["User principal name"].dropna().astype(str).str.lower()
        
        # Filtra apenas os e-mails do domínio correto
        vmis_emails = {email for email in email_list if email.endswith(app.config["ALLOWED_DOMAIN"])}
        
        app.logger.info(f"✅ {len(vmis_emails)} e-mails autorizados ({app.config['ALLOWED_DOMAIN']}) carregados com sucesso.")
        return vmis_emails
        
    except Exception as e:
        app.logger.error(f"❌ FALHA CRÍTICA ao ler 'users.xlsx': {e}")
        return set()

# CARREGA OS E-MAILS NA INICIALIZAÇÃO DO APP
AUTHORIZED_EMAIL_SET = load_authorized_emails()
# ---------------------------------------------------

SERVICOS = [
    "IMAGESERVICE", "DETECTORAPI", "CALIBRATIONAPI", "FILEMANAGERAPI",
    "MCBCOMMUNICATIONAPI", "DETECTORCOMMUNICATION", "USERAPI", "SETTINGSAPI",
    "PERIPHERALSAPI", "CONVEYORBELTAPI", "REPORTAPI", "INSPECTIONAPI",
    "GENERATORAPI", "RABBTIMQ", "LOGSTASH", "MONGO-EXPRESS"
]

# --- FUNÇÃO AUXILIAR DE TEXTO PARA PDF (APRIMORADA) ---
def clean_text(text):
    if not isinstance(text, str):
        text = str(text)
    text = re.sub('<[^<]+?>', '', text)
    text = text.replace('ç', 'c').replace('Ç', 'C')
    text = re.sub(r'[áàãâä]', 'a', text, flags=re.IGNORECASE)
    text = re.sub(r'[éèêë]', 'e', text, flags=re.IGNORECASE)
    text = re.sub(r'[íìîï]', 'i', text, flags=re.IGNORECASE)
    text = re.sub(r'[óòõôö]', 'o', text, flags=re.IGNORECASE)
    text = re.sub(r'[úùûü]', 'u', text, flags=re.IGNORECASE)
    text = text.replace('º', '').replace('ª', '')
    text = text.replace('—', '-').replace('–', '-')
    return text.encode('latin-1', 'replace').decode('latin-1')

# --- Banco de Dados: Funções (sem alterações) ---
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
        return False # E-mail já existe
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

# --- ROTA DE REGISTRO MODIFICADA ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password') # <-- CAMPO ADICIONADO

        # Verificação 1: Campos preenchidos
        if not email or not password or not confirm_password:
            flash('Por favor, preencha todos os campos.', 'danger')
            return render_template('register.html')
        
        # Verificação 2: Senhas coincidem
        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('register.html')

        # Verificação 3: Comprimento da senha (boa prática)
        if len(password) < 6:
            flash('A senha deve ter pelo menos 6 caracteres.', 'danger')
            return render_template('register.html')

        # Verificação 4: Domínio
        if not is_valid_email(email):
            flash(f"O e-mail deve pertencer ao domínio {app.config['ALLOWED_DOMAIN']}.", 'danger')
            return render_template('register.html')
            
        # Verificação 5: E-mail autorizado no .xlsx (Nova regra)
        if email not in AUTHORIZED_EMAIL_SET:
            app.logger.warning(f"Tentativa de cadastro falhou: E-mail '{email}' não está na lista de autorizados (users.xlsx).")
            flash('❌ E-mail não autorizado para cadastro.', 'danger')
            return render_template('register.html')
            
        # Verificação 6: E-mail já existe no banco de dados
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        if insert_user(email, hashed_password):
            app.logger.info(f"Novo usuário cadastrado: {email}")
            flash('✅ Cadastro realizado com sucesso! Faça seu login.', 'success')
            return redirect(url_for('login')) 
        else:
            flash('❌ Este e-mail já está cadastrado no sistema. Tente outro ou faça login.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')
# ------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session:
        session.pop("is_admin", None)
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email").strip().lower()
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

# ... (O restante do seu app.py continua aqui, sem alterações) ...
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
                flash("🚫 Permissão negada. Apenas administradores podem apagar erros.", "danger")
                return redirect(url_for("dashboard"))
            
            id_str = request.form.get("id")
            id_to_delete = None
            try:
                id_to_delete = int(id_str)
            except (ValueError, TypeError):
                flash("❌ ID de erro inválido para exclusão.", "danger")
                return redirect(url_for("dashboard"))
            
            if id_to_delete is not None:
                if delete_erro(id_to_delete):
                    flash("✅ Erro apagado com sucesso!", "success")
                else:
                    flash("❌ Erro ao apagar. O ID pode não existir ou houve um problema no banco de dados.", "danger")
            else:
                 flash("❌ ID de erro inválido para exclusão.", "danger")
        
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
    erros = fetch_all_erros()
    try:
        pdf = FPDF()
        LINE_HEIGHT = 6
        LABEL_WIDTH = 20
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 18) 
        pdf.cell(0, 10, clean_text("Relatório de Erros Cadastrados"), ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 5, clean_text(f"Gerado por: {session.get('user', 'Desconhecido')}"), ln=True, align="C")
        pdf.ln(5)
        
        for r in erros:
            if pdf.get_y() > 270: 
                pdf.add_page()
            
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, LINE_HEIGHT, 
                     clean_text(f"ID: {r['id']} | Serviço: {r['servico']} | Criado por: {r['criado_por'].split('@')[0]}"), 
                     1, 1, 'L', True)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Arial', '', 10)
            pdf.ln(1)
            
            pdf.set_font('Arial', 'B', 10)
            pdf.set_x(pdf.l_margin)
            pdf.cell(LABEL_WIDTH, LINE_HEIGHT, "Erro:", 0, 0, 'L')
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, LINE_HEIGHT, clean_text(r['erro']), 0, 'L')

            pdf.set_font('Arial', 'B', 10)
            pdf.set_x(pdf.l_margin)
            pdf.cell(LABEL_WIDTH, LINE_HEIGHT, "Solução:", 0, 0, 'L')
            
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, LINE_HEIGHT, clean_text(r['solucao']), 0, 'L')

            pdf.ln(1)
            pdf.set_draw_color(150, 150, 150)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(2)

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