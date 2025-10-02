import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import csv

# PDF opcional
try:
    from fpdf import FPDF
    HAVE_PDF = True
except Exception:
    HAVE_PDF = False

# caminho do DB (diretório home do usuário)
DB_PATH = os.path.join(os.path.expanduser("~"), "troubleshoot.db")

# ----- Helpers para banco e migração -----
def ensure_schema_and_migrate(db_path):
    """Garante que a tabela 'erros' tenha as colunas esperadas.
       Se existir com esquema diferente, tenta migrar os dados preservando valores possíveis."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # existe tabela?
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='erros'")
    if not cur.fetchone():
        # criar tabela correta
        cur.execute("""
            CREATE TABLE erros (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                erro TEXT NOT NULL,
                servico TEXT NOT NULL,
                solucao TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        return

    # se existir, ver colunas atuais
    cur.execute("PRAGMA table_info(erros)")
    cols_info = cur.fetchall()
    existing_cols = [c[1] for c in cols_info]

    desired = {"id", "erro", "servico", "solucao"}
    if desired.issubset(set(existing_cols)):
        # já possui as colunas necessárias
        conn.close()
        return

    # precisa migrar: vamos ler tudo da tabela antiga, mapear e criar nova tabela preservando dados
    cur.execute("SELECT * FROM erros")
    old_rows = cur.fetchall()
    old_col_names = existing_cols  # índice corresponde ao tuple index

    # criar tabela temporária nova
    cur.execute("""
        CREATE TABLE IF NOT EXISTS erros_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            erro TEXT NOT NULL,
            servico TEXT NOT NULL,
            solucao TEXT NOT NULL
        )
    """)
    # mapear cada row antigo para a nova estrutura
    for row in old_rows:
        row_dict = {}
        for i, colname in enumerate(old_col_names):
            row_dict[colname] = row[i]
        # tenta extrair os valores por vários nomes possíveis
        erro_val = row_dict.get("erro") or row_dict.get("mensagem") or row_dict.get("message") or row_dict.get("descricao") or row_dict.get("error") or ""
        servico_val = row_dict.get("servico") or row_dict.get("service") or row_dict.get("serviço") or ""
        solucao_val = row_dict.get("solucao") or row_dict.get("solucao_text") or row_dict.get("solution") or row_dict.get("descricao") or ""
        # tenta preservar id se existir
        id_val = row_dict.get("id")
        if id_val is not None:
            try:
                cur.execute("INSERT INTO erros_new (id, erro, servico, solucao) VALUES (?, ?, ?, ?)",
                            (id_val, erro_val, servico_val, solucao_val))
            except sqlite3.IntegrityError:
                # id duplicado; insere sem id
                cur.execute("INSERT INTO erros_new (erro, servico, solucao) VALUES (?, ?, ?)",
                            (erro_val, servico_val, solucao_val))
        else:
            cur.execute("INSERT INTO erros_new (erro, servico, solucao) VALUES (?, ?, ?)",
                        (erro_val, servico_val, solucao_val))

    conn.commit()
    # remover tabela antiga e renomear a nova
    cur.execute("DROP TABLE erros")
    cur.execute("ALTER TABLE erros_new RENAME TO erros")
    conn.commit()
    conn.close()

def connect():
    return sqlite3.connect(DB_PATH)

# ----- Operações de dados -----
def fetch_all_erros():
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT id, erro, servico, solucao FROM erros ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows

def insert_erro(erro, servico, solucao):
    conn = connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO erros (erro, servico, solucao) VALUES (?, ?, ?)", (erro, servico, solucao))
    conn.commit()
    conn.close()

def update_erro(id_, erro, servico, solucao):
    conn = connect()
    cur = conn.cursor()
    cur.execute("UPDATE erros SET erro=?, servico=?, solucao=? WHERE id=?", (erro, servico, solucao, id_))
    conn.commit()
    conn.close()

def delete_erro(id_):
    conn = connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM erros WHERE id=?", (id_,))
    conn.commit()
    conn.close()

# ----- UI handlers -----
def carregar_treeview():
    tree.delete(*tree.get_children())
    for r in fetch_all_erros():
        # para exibir no treeview substituímos quebras de linha por ' | '
        sol_format = r[3].replace("\n", " | ")
        tree.insert("", tk.END, values=(r[0], r[1], r[2], sol_format))

def cadastrar_handler():
    msg = entry_msg.get().strip()
    srv = combo_srv.get().strip()
    sol = entry_sol.get("1.0", tk.END).strip()
    if not msg or not srv or not sol:
        messagebox.showwarning("Aviso", "Preencha todos os campos!")
        return
    # verifica duplicidade (erro + serviço)
    for row in fetch_all_erros():
        if row[1].strip().lower() == msg.lower() and row[2] == srv:
            messagebox.showwarning("Aviso", "Erro já cadastrado para este serviço!")
            return
    insert_erro(msg, srv, sol)
    carregar_treeview()
    limpar_handler()
    messagebox.showinfo("Sucesso", "Erro cadastrado com sucesso!")

def limpar_handler():
    entry_msg.delete(0, tk.END)
    combo_srv.set("")
    entry_sol.delete("1.0", tk.END)

def apagar_handler():
    sel = tree.selection()
    if not sel:
        return
    for item in sel:
        vals = tree.item(item, "values")
        delete_erro(vals[0])
    carregar_treeview()

def buscar_handler():
    termo = entry_msg.get().strip().lower()
    tree.delete(*tree.get_children())
    for r in fetch_all_erros():
        if termo in r[1].lower():
            tree.insert("", tk.END, values=(r[0], r[1], r[2], r[3].replace("\n", " | ")))

def alterar_handler():
    sel = tree.selection()
    if not sel:
        messagebox.showwarning("Aviso", "Selecione um erro para alterar.")
        return
    item = sel[0]
    vals = tree.item(item, "values")
    id_ = vals[0]
    msg = entry_msg.get().strip()
    srv = combo_srv.get().strip()
    sol = entry_sol.get("1.0", tk.END).strip()
    if not msg or not srv or not sol:
        messagebox.showwarning("Aviso", "Preencha todos os campos!")
        return
    # verifica duplicidade em outro id
    for r in fetch_all_erros():
        if r[0] != id_ and r[1].strip().lower() == msg.lower() and r[2] == srv:
            messagebox.showwarning("Aviso", "Outro registro com mesmo erro e serviço já existe!")
            return
    update_erro(id_, msg, srv, sol)
    carregar_treeview()
    limpar_handler()
    messagebox.showinfo("Sucesso", "Erro atualizado!")

def on_double_click(event):
    sel = tree.selection()
    if not sel:
        return
    item = sel[0]
    vals = tree.item(item, "values")
    # preencher campos para edição (mantendo a solução com quebras de linha)
    entry_msg.delete(0, tk.END)
    entry_msg.insert(0, vals[1])
    combo_srv.set(vals[2])
    # pegar solução completa do DB
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT solucao FROM erros WHERE id=?", (vals[0],))
    row = cur.fetchone()
    conn.close()
    sol_text = row[0] if row and row[0] is not None else ""
    entry_sol.delete("1.0", tk.END)
    entry_sol.insert(tk.END, sol_text)
    # foco nos campos prontos para alterar
    entry_msg.focus_set()

# Exportar
def exportar_csv_handler():
    rows = fetch_all_erros()
    if not rows:
        messagebox.showinfo("Exportar", "Não há erros para exportar.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
    if not path:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Erro", "Serviço", "Solução"])
        writer.writerows(rows)
    messagebox.showinfo("Exportar", f"Exportado para {path}")

def exportar_pdf_handler():
    if not HAVE_PDF:
        messagebox.showerror("Dependência", "FPDF não instalado. Rode: pip install fpdf")
        return
    rows = fetch_all_erros()
    if not rows:
        messagebox.showinfo("Exportar", "Não há erros para exportar.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
    if not path:
        return
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Erros Cadastrados", ln=True, align="C")
    pdf.ln(5)
    for r in rows:
        pdf.multi_cell(0, 8, f"ID: {r[0]}\nErro: {r[1]}\nServiço: {r[2]}\nSolução:\n{r[3]}\n" + "-"*40)
        pdf.ln(2)
    pdf.output(path)
    messagebox.showinfo("Exportar", f"PDF salvo em {path}")

# ----- Interface -----
ensure_schema_and_migrate(DB_PATH)

root = tk.Tk()
root.title("Troubleshoot Manager")
root.configure(bg="black")

# maximizar conforme SO
try:
    root.state("zoomed")
except Exception:
    root.attributes("-zoomed", True)

style = ttk.Style()
style.configure("TLabel", background="black", foreground="darkorange")
style.configure("TButton", background="black", foreground="darkorange")
style.configure("Treeview", background="black", foreground="darkorange", fieldbackground="black")
style.map("Treeview", background=[('selected', 'darkorange')], foreground=[('selected', 'black')])

# logo canto superior esquerdo
try:
    logo_img = Image.open("logo.png")
    logo_img = logo_img.resize((150, 80))
    logo = ImageTk.PhotoImage(logo_img)
    logo_label = tk.Label(root, image=logo, bg="black")
    logo_label.pack(anchor="nw", padx=10, pady=(10,5))
except Exception:
    # se não houver logo, apenas continue
    pass

# frame para menu (abaixo da logo) alinhado à esquerda
top_buttons_frame = tk.Frame(root, bg="black")
top_buttons_frame.pack(fill=tk.X, anchor="nw", padx=10, pady=(0,8))

# Menubutton Opções
btn_opcoes = tk.Menubutton(top_buttons_frame, text="Opções", bg="black", fg="darkorange",
                           bd=2, relief="solid", takefocus=0)
menu = tk.Menu(btn_opcoes, tearoff=0, bg="black", fg="darkorange")
menu.add_command(label="Exportar CSV", command=exportar_csv_handler)
menu.add_command(label="Exportar PDF", command=exportar_pdf_handler)
menu.add_separator()
menu.add_command(label="Sair", command=root.destroy)
btn_opcoes.config(menu=menu)
btn_opcoes.pack(side=tk.LEFT, padx=5)


# botão Sobre ao lado
btn_sobre = tk.Button(
    top_buttons_frame,
    text="Sobre",
    command=lambda: messagebox.showinfo(
        "Sobre",
        "Autor: Maicon Ferreira\nAnalista de Testes II\nVersão 1.0\nContato: maicon.ferreira@vmis.com.br\nProjeto: Troubleshoot Manager"
    ),
    bg="black",
    fg="darkorange",
    bd=2,
    relief="solid",
    takefocus=0
)
btn_sobre.pack(side=tk.LEFT, padx=5)

# frame de botões principais (Limpar, Cadastrar, Buscar, Alterar, Apagar)
crud_frame = tk.Frame(root, bg="black")
crud_frame.pack(fill=tk.X, padx=10, pady=(0,6), anchor="nw")
ttk.Button(crud_frame, text="Limpar", command=limpar_handler).pack(side=tk.LEFT, padx=4)
ttk.Button(crud_frame, text="Cadastrar", command=cadastrar_handler).pack(side=tk.LEFT, padx=4)
ttk.Button(crud_frame, text="Buscar", command=buscar_handler).pack(side=tk.LEFT, padx=4)
ttk.Button(crud_frame, text="Alterar", command=alterar_handler).pack(side=tk.LEFT, padx=4)
ttk.Button(crud_frame, text="Apagar", command=apagar_handler).pack(side=tk.LEFT, padx=4)

# campos
ttk.Label(root, text="Mensagem de Erro:").pack(anchor="w", padx=10)
entry_msg = tk.Entry(root, width=100)
entry_msg.pack(padx=10, pady=4, fill=tk.X)

ttk.Label(root, text="Serviço:").pack(anchor="w", padx=10)
SERVICOS = [
    "IMAGESERVICE", "DETECTORAPI", "CALIBRATIONAPI", "FILEMANAGERAPI",
    "MCBCOMMUNICATIONAPI", "DETECTORCOMMUNICATION", "USERAPI", "SETTINGSAPI",
    "PERIPHERALSAPI", "CONVEYORBELTAPI", "REPORTAPI", "INSPECTIONAPI",
    "GENETORAPI", "RABBTIMQ", "LOGSTASH", "MONGO-EXPRESS"
]
combo_srv = ttk.Combobox(root, values=SERVICOS, state="readonly")
combo_srv.pack(padx=10, pady=4, fill=tk.X)

ttk.Label(root, text="Possível Solução:").pack(anchor="w", padx=10)
entry_sol = tk.Text(root, height=8, wrap="word")
entry_sol.pack(padx=10, pady=4, fill=tk.X)

# Treeview
tree = ttk.Treeview(root, columns=("ID", "Erro", "Serviço", "Solução"), show="headings")
tree.heading("ID", text="ID"); tree.column("ID", width=60, anchor="center")
tree.heading("Erro", text="Erro"); tree.column("Erro", width=400)
tree.heading("Serviço", text="Serviço"); tree.column("Serviço", width=180)
tree.heading("Solução", text="Possível Solução"); tree.column("Solução", width=500)
tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
tree.bind("<Double-1>", on_double_click)

# remove foco do botão Sobre e garante foco na janela principal
root.update_idletasks()
root.focus_set()

# carregar dados
carregar_treeview()

root.mainloop()
