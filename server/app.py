from flask import Flask, request, render_template, url_for, redirect
from flask import session, flash
from werkzeug.security import check_password_hash, generate_password_hash
import peewee
import os
from dotenv import load_dotenv
from model.models import db, StatusMessage, User, GitHubInstallation

from routes.api_routes import api_bp
from routes.auth_routes import auth_bp
from routes.discord_routes import discord_bp
from routes.github_routes import github_bp

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

app.register_blueprint(api_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(discord_bp)
app.register_blueprint(github_bp)

# Garantir a criação das tabelas e usuários de teste
with db:
    db.create_tables([User, GitHubInstallation])

    try:
        User.get(User.username == 'adm')
    except peewee.DoesNotExist:
        hashed_password = generate_password_hash('123')
        User.create(username='adm', password_hash=hashed_password)
        print("Usuário 'adm' criado com a senha padrão '123'.")


# Gerenciamento de conexão com o banco de dados por requisição
@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response


# ----- Login/Logou ----- #
@app.route("/", methods=["GET"])
def home():

    status_message = request.args.get("status_message")

    if "user_id"  in session:
        try:
            user = User.get_by_id(session['user_id'])
            return render_template("main/home.html", logged_in=True, logged_out=False, user=user)
        except peewee.DoesNotExist:
            session.clear()
            return render_template("main/home.html", logged_in=False, logged_out=False)
    
    elif status_message:
        return render_template("main/home.html", logged_in=False, logged_out=True, status_message=status_message)

    else:
        return render_template("main/home.html", logged_in=False, logged_out=False)


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.get_or_none(User.username == username)

        if user and user.password_hash and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            flash("You are logged in!", "success")
            return redirect(url_for('home'))
        else:
            flash("Wrong Credentials", "danger")
            return redirect(url_for('login'))
    return render_template("main/login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST": 
        username = request.form["username"]
        password = request.form["password"]

        if User.get_or_none(User.username == username):
            flash("Username already exists", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)  
        User.create(username=username, password_hash=hashed_password)
        
        flash("You are registered!", "success")
        return redirect(url_for("login"))
    return render_template("main/register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You logged out!", "info")
    return redirect(url_for("home", logged_out=True))


@app.route("/manage", methods=["GET"])
def choose_manager():

    user_id = None
    logged_in = False

    if "user_id" in session:
        user_id = session["user_id"]

    #Caso não tenha um id informado (ex: ?user_id=1)
    if not user_id:
        return render_template("manage/choose_manager.html",
                               logged_in=logged_in, status_message=StatusMessage(message="You need to login"), code=400, is_error=True)

    try:
        user = User.get(id=user_id)
        logged_in = True
        
        return render_template("manage/choose_manager.html",
                                user=user, logged_in=logged_in, status_message=StatusMessage()
        )

    # caso o usuário não exista
    except peewee.DoesNotExist:
        error = StatusMessage("Something bad happened, come back again later...", log_message="User is logged in but do not exists on Database",code=500, is_error=True)
        return render_template("manage/choose_manager.html", error=error)


if __name__ == "__main__":
    app.run(debug=True)