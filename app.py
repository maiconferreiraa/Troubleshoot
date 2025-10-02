import os
import sqlite3
import csv
import secrets
import time
from io import StringIO, BytesIO
from fpdf import FPDF
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Configuração da Aplicação ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "troubleshoot_v2.db")
ALLOWED_DOMAIN = "@vmis.com.br"
# ALTERADO: Email do administrador.
ADMIN_EMAIL = "maicon.ferreira@vmis.com.br"
# Use uma chave SECRETA longa e única para produção
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "sua_chave_secreta_muito_forte_12345") 

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["DB_PATH"] = DB_PATH
app.config["ALLOWED_DOMAIN"] = ALLOWED_DOMAIN
app.config["ADMIN_EMAIL"] = ADMIN_EMAIL

# Lista de serviços movida para a configuração da aplicação
SERVICOS = [
    "IMAGESERVICE", "DETECTORAPI", "CALIBRATIONAPI", "FILEMANAGERAPI",
    "MCBCOMMUNICATIONAPI", "DETECTORCOMMUNICATION", "USERAPI", "SETTINGSAPI",
    "PERIPHERALSAPI", "CONVEYORBELTAPI", "REPORTAPI", "INSPECTIONAPI",
    "GENERATORAPI", "RABBTIMQ", "LOGSTASH", "MONGO-EXPRESS"
]


# --- Banco de Dados: Funções e Context Manager ---

def get_db_connection():
    """Retorna uma conexão SQLite e configura o row_factory para usar sqlite3.Row."""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa o banco de dados e cria as tabelas 'erros', 'users' e 'tokens'."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            # 1. Tabela de Erros
            cur.execute("""
                CREATE TABLE IF NOT EXISTS erros (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    erro TEXT NOT NULL,
                    servico TEXT NOT NULL,
                    solucao TEXT NOT NULL
                )
            """)
            # 2. Tabela de Usuários
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
            # 3. Tabela de Tokens de Redefinição de Senha
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_email TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    expiration_time INTEGER NOT NULL 
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o DB: {e}")

# --- Funções CRUD de Erros (Omitidas para foco, mas presentes no seu código) ---
def fetch_all_erros():
    """Busca todos os erros cadastrados."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, erro, servico, solucao FROM erros ORDER BY id DESC")
            return cur.fetchall()
    except sqlite3.Error as e:
        print(f"Erro ao buscar erros: {e}")
        return []

def insert_erro(erro, servico, solucao):
    """Insere um novo erro no banco de dados."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO erros (erro, servico, solucao) VALUES (?, ?, ?)", (erro, servico, solucao))
            conn.commit()
            return True
    except sqlite3.Error as e:
        print(f"Erro ao inserir erro: {e}")
        return False

def update_erro(id_, erro, servico, solucao):
    """Atualiza um erro existente no banco de dados."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE erros SET erro=?, servico=?, solucao=? WHERE id=?", (erro, servico, solucao, id_))
            conn.commit()
            return cur.rowcount > 0
    except sqlite3.Error as e:
        print(f"Erro ao atualizar erro: {e}")
        return False

def delete_erro(id_):
    """Deleta um erro do banco de dados pelo ID."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM erros WHERE id=?", (id_,))
            conn.commit()
            return cur.rowcount > 0
    except sqlite3.Error as e:
        print(f"Erro ao deletar erro: {e}")
        return False


# --- Funções CRUD de Usuários e Tokens ---

def insert_user(email, password_hash):
    """Insere um novo usuário no banco de dados."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error as e:
        print(f"Erro ao inserir usuário: {e}")
        return False

def fetch_user_by_email(email):
    """Busca um usuário pelo email."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
            return cur.fetchone()
    except sqlite3.Error as e:
        print(f"Erro ao buscar usuário: {e}")
        return None

def create_reset_token(email):
    """Cria e armazena um token de redefinição de senha."""
    try:
        # Gera um token seguro de 32 bytes (64 caracteres hex)
        token = secrets.token_hex(32)
        # Token expira em 2 horas (7200 segundos)
        expiration_time = int(time.time()) + 7200
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            # Limpa tokens antigos para este usuário (opcional, mas bom)
            cur.execute("DELETE FROM password_reset_tokens WHERE user_email = ?", (email,))
            
            # Insere o novo token
            cur.execute(
                "INSERT INTO password_reset_tokens (user_email, token, expiration_time) VALUES (?, ?, ?)", 
                (email, token, expiration_time)
            )
            conn.commit()
            return token
    except sqlite3.Error as e:
        print(f"Erro ao criar token: {e}")
        return None

def get_token_info(token):
    """Busca e valida um token de redefinição."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT user_email, expiration_time FROM password_reset_tokens WHERE token = ?", (token,))
            row = cur.fetchone()
            
            if row and row["expiration_time"] > int(time.time()):
                return row["user_email"]
            # Token expirado ou não encontrado
            return None
    except sqlite3.Error as e:
        print(f"Erro ao buscar token: {e}")
        return None

def delete_reset_token(token):
    """Remove o token após o uso."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Erro ao deletar token: {e}")


def update_user_password(email, new_password_hash):
    """Atualiza o hash da senha de um usuário."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password_hash = ? WHERE email = ?", (new_password_hash, email))
            conn.commit()
            return cur.rowcount > 0
    except sqlite3.Error as e:
        print(f"Erro ao atualizar senha: {e}")
        return False


# --- Funções de Login e Decorador de Autenticação ---

def is_valid_email(email):
    """Verifica se o email termina com o domínio permitido e não é vazio."""
    return email and email.strip().lower().endswith(app.config["ALLOWED_DOMAIN"])

def login_required(f):
    """Decorador para proteger rotas. Redireciona para o login se o usuário não estiver na sessão."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Você precisa fazer login para acessar esta página.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# --- Rotas de Autenticação Comum ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Lida com a lógica de cadastro de um novo usuário."""
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
    """Lida com a lógica de login baseada no DB."""
    if "user" in session:
        # Limpa o status de admin se o usuário logar pela rota comum
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
                    # Define o status de admin como False explicitamente se logar por aqui
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
    """
    Rota de login exclusiva para o administrador. 
    Define 'is_admin' como True na sessão se o login for bem-sucedido com o ADMIN_EMAIL.
    """
    error_message = None

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password") 
        
        user_row = fetch_user_by_email(email)
        
        # 1. Checa as credenciais normalmente
        if user_row and check_password_hash(user_row["password_hash"], password) and is_valid_email(email):
            # 2. SE o usuário for o ADMIN_EMAIL, concede o status de administrador
            if email.lower() == app.config["ADMIN_EMAIL"]:
                session["user"] = email
                session["is_admin"] = True
                flash("ADMINISTRADOR: Acesso total concedido.", "warning")
                return redirect(url_for("dashboard"))
            else:
                 # CORRIGIDO: Usa a variável local em vez de flash() global
                 error_message = f"Acesso negado. Apenas o e-mail {app.config['ADMIN_EMAIL']} pode usar esta rota."
                 
        elif user_row:
             error_message = "Senha incorreta ou domínio inválido."
        else:
             error_message = "E-mail não encontrado."
            
    # Passa a mensagem de erro local (ou None) para o template
    return render_template("admin_login.html", admin_email=app.config["ADMIN_EMAIL"], error_message=error_message)


@app.route("/logout")
def logout():
    """Limpa a sessão e redireciona para a página de login."""
    session.pop("user", None)
    session.pop("is_admin", None) # Limpa o status de admin
    flash("Você foi desconectado com sucesso.", "info")
    return redirect(url_for("login"))


# --- Rotas de Recuperação de Senha ---

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    """Solicita a redefinição de senha e simula o envio de e-mail."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if fetch_user_by_email(email):
            token = create_reset_token(email)
            if token:
                # SIMULAÇÃO DE E-MAIL: Imprime o link no console para teste
                reset_link = url_for('reset_password', token=token, _external=True)
                print("-" * 50)
                print(f"SIMULAÇÃO DE E-MAIL para {email}:")
                print(f"CLIQUE AQUI PARA REDEFINIR SENHA: {reset_link}")
                print("-" * 50)
                flash('Se o seu e-mail estiver em nosso sistema, você receberá um link para redefinição de senha.', 'info')
        else:
             flash('Se o seu e-mail estiver em nosso sistema, você receberá um link para redefinição de senha.', 'info')
        
        return redirect(url_for('login'))
        
    return render_template('password_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Permite ao usuário redefinir a senha usando um token válido."""
    
    email_to_reset = get_token_info(token)
    
    if not email_to_reset:
        flash("Link de redefinição inválido ou expirado.", "danger")
        return redirect(url_for('password_reset'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("As senhas não coincidem.", "danger")
            # Renderiza a página novamente, mantendo o token na URL
            return render_template('reset_password.html', token=token)
            
        if len(password) < 6: # Exemplo simples de validação de senha
            flash("A senha deve ter pelo menos 6 caracteres.", "danger")
            return render_template('reset_password.html', token=token)

        # Atualiza a senha no DB
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        if update_user_password(email_to_reset, hashed_password):
            delete_reset_token(token) # Remove o token após o uso
            flash('✅ Senha redefinida com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Erro ao redefinir a senha. Tente novamente.', 'danger')

    # Se GET, apenas renderiza o formulário
    return render_template('reset_password.html', token=token)


# --- Dashboard e CRUD ---

@app.route("/dashboard", methods=["GET", "POST"])
@login_required 
def dashboard():
    """Lida com a exibição do dashboard e todas as operações CRUD."""
    
    # Verifica o status de admin para exibir ou ocultar botões
    is_admin = session.get("is_admin", False)

    # Processamento de POST (CRUD)
    if request.method == "POST":
        action = request.form.get("action")
        
        # Função auxiliar para sanitizar e validar dados
        def get_validated_data(is_update=False):
            data = {
                "erro": request.form.get("erro", "").strip(),
                "servico": request.form.get("servico", "").strip(),
                "solucao": request.form.get("solucao", "").strip()
            }
            if is_update:
                id_str = request.form.get("id", "")
                data["id"] = int(id_str) if id_str.isdigit() else None
            
            if not all(k in data and data[k] for k in ["erro", "servico", "solucao"]) or (is_update and data.get("id") is None):
                 flash("Preencha todos os campos obrigatórios.", "warning")
                 return None
            return data

        if action == "cadastrar":
            data = get_validated_data()
            if data and insert_erro(data["erro"], data["servico"], data["solucao"]):
                flash("Erro cadastrado com sucesso!", "success")
            elif data:
                flash("Erro ao cadastrar. Tente novamente.", "danger")
                
        elif action == "alterar":
            data = get_validated_data(is_update=True)
            if data and data["id"] is not None and update_erro(data["id"], data["erro"], data["servico"], data["solucao"]):
                flash("Erro atualizado!", "success")
            elif data:
                flash("Erro ao atualizar ou ID inválido.", "danger")
                
        elif action == "apagar":
            # RESTRICAO CRITICA: Ação de apagar é somente para administradores
            if not is_admin:
                # Se um usuário comum tentar apagar (e burlar o front-end), bloqueia e redireciona
                flash("Permissão negada. Apenas administradores podem apagar.", "danger")
                return redirect(url_for("dashboard"))
                
            id_str = request.form.get("id")
            if id_str and id_str.isdigit() and delete_erro(int(id_str)):
                flash("Erro apagado!", "success")
            else:
                flash("Erro ao apagar ou ID inválido.", "danger")
        
        return redirect(url_for("dashboard"))

    # Processamento de GET (Exibição)
    erros = fetch_all_erros()
    # Passa o status de admin para o template controlar a exibição dos botões
    return render_template("dashboard.html", 
                           erros=erros, 
                           servicos=SERVICOS, 
                           user=session["user"], 
                           is_admin=is_admin)

# --- Rotas de Exportação (Omitidas para foco, mas presentes no seu código) ---

@app.route("/export/csv")
@login_required
def export_csv():
    """Exporta todos os erros para um arquivo CSV."""
    erros = fetch_all_erros()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID", "Erro", "Serviço", "Solução"])
    writer.writerows([tuple(row) for row in erros])
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
    """Exporta todos os erros para um arquivo PDF usando FPDF."""
    erros = fetch_all_erros()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    
    pdf.cell(0, 10, "Erros Cadastrados", ln=True, align="C")
    pdf.ln(10)
    
    for r in erros:
        def clean_text(text):
            return text.encode('latin-1', 'replace').decode('latin-1')

        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, clean_text(f"ID: {r['id']} - Servico: {r['servico']}"))
        pdf.ln()

        pdf.set_font("Arial", "", 11)
        pdf.multi_cell(0, 6, clean_text(f"Erro: {r['erro']}"))
        pdf.multi_cell(0, 6, clean_text(f"Solucao: {r['solucao']}"))
        pdf.ln(5)

    pdf_output = pdf.output(dest='S').encode('latin-1')
    
    return send_file(
        BytesIO(pdf_output),
        mimetype="application/pdf", 
        as_attachment=True, 
        download_name="erros_cadastrados.pdf"
    )


# --- Execução ---

if __name__ == "__main__":
    with app.app_context():
        init_db() # Inicializa as tabelas erros, users E tokens
    app.run(debug=True, host='0.0.0.0')
