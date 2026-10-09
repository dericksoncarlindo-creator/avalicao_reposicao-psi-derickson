from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import database, conectar, Usuario, criar_usuario

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nome = request.form["nome"]
        email = request.form["email"]
        senha = request.form["senha"]

        conn = conectar()
        usuario = conn.execute("SELECT id FROM user WHERE email = ?", (email,)).fetchone()

        if usuario:
            conn.close()
            flash("Email já cadastrado.")
            return redirect(url_for("registro"))

        senha_hash = generate_password_hash(senha)
        conn.execute("INSERT INTO user (nome, email, senha) VALUES (?, ?, ?)", (nome, email, senha_hash))
        conn.commit()
        conn.close()
        return redirect(url_for("auth.registro"))

    return render_template("registro.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]

        conn = conectar()
        user_row = conn.execute("SELECT * FROM user WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user_row and check_password_hash(user_row["senha"], senha):
            usuario = Usuario(user_row["id"],user_row["nome"], user_row["email"], user_row["senha"])
            criar_usuario(usuario)
        return redirect(url_for("auth.login"))
    session["usuario_id"] = usuario.id
    session["usuario_nome"] = usuario.nome
    session.commit()
    
    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
