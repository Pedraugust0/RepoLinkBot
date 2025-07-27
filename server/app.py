from flask import Flask, request, render_template, url_for, redirect
import peewee
import requests
import os
from dotenv import load_dotenv
from model.models import db, Error, User

from flask import session, flash, get_flashed_messages
from werkzeug.security import check_password_hash, generate_password_hash
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

# Gerenciamento de conexão com o banco de dados por requisição
@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

with db:
    db.create_tables([User])
    # Cria o usuário 'adm' com senha '123' se ele não existir
    try:
        User.get(User.username == 'adm')
    except peewee.DoesNotExist:
        hashed_password = generate_password_hash('123')
        User.create(username='adm', password_hash=hashed_password)
        print("Usuário 'adm' criado com a senha padrão '123'.")


GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = "http://127.0.0.1:5000/github/callback"

DISCORD_CLIENT_ID= os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET= os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI= "http://127.0.0.1:5000/discord/callback"

# ----- Login/Logou ----- #
@app.route("/", methods=["GET"])
def home():
    if 'user_id' in session:
        try:
            user = User.get_by_id(session['user_id'])
            return render_template("main/home.html", logged_in=True, logged_out=False, user=user)
        except peewee.DoesNotExist:
            session.clear()
            return render_template("main/home.html", logged_in=False, logged_out=False)
    
    elif bool(get_flashed_messages(with_categories=True)):
        return render_template("main/home.html", logged_in=False, logged_out=True)

    else:
        return render_template("main/home.html", logged_in=False, logged_out=False)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.get_or_none(User.username == username)

        if user and user.password_hash and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
            return redirect(url_for('login'))
        
    return render_template("main/login.html")

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.get_or_none(User.username == username)

        if user and user.password_hash and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
            return redirect(url_for('login'))
        
    return render_template("main/login.html")

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('home', logged_out=True))

# ----- Endpoints ----- #

@app.route("/manage", methods=["GET"])
def choose_manager():

    user_id = None
    logged_in = False

    if "user_id" in session:
        user_id = session["user_id"]

    #Caso não tenha um id informado (ex: ?user_id=1)
    if not user_id:
        flash('Você precisa fazer login.', 'danger')
        return render_template("manage/choose_manager.html",
                               logged_in=logged_in)

    try:
        user = User.get(id=user_id)
        logged_in = True

        return render_template("manage/choose_manager.html",
                                user=user, logged_in=logged_in
        )

    # caso o usuário não exista
    except peewee.DoesNotExist:
        error = Error("Id inválido!")
        return render_template("manage/choose_manager.html", error=error)


# Endpoint de resposta da autenticação
@app.route("/auth/connection_response", methods=["GET"])
def auth_connection_response():
    message = request.args.get("message")
    code = request.args.get("code")

    return render_template("connection/connection_response.html",
                            message=message,
                            code=code)


# ----- AUTENTICAÇÃO OAuth2 ----- #

# Rota para link de autorização
@app.route("/auth/discord")
def auth_discord():
    
    authorize_url = (
        "https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={DISCORD_REDIRECT_URI}&"
        "response_type=code&"
        r"scope=identify%20guilds"
    )

    return redirect(authorize_url)


# Rota para fazer a troca do código de autorização pelo token do github
@app.route("/discord/callback")
def discord_callback():
    code = request.args.get("code")

    if not code:
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Código de autorização não recebido.", 
                                code=400))
    
    token_url = "https://discord.com/api/oauth2/token"
    headers = {"Accept": "application/json"}
    payload = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }

    resposta = requests.post(url=token_url, headers=headers, data=payload)
    tokens_data = resposta.json()
    access_token = tokens_data.get("access_token")

    if not access_token:
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Não foi possível receber o token de acesso do Discord", 
                                code=500))

    # Sucesso
    return redirect(url_for("auth_connection_response", message="Conta do Discord conectada com sucesso!", code=200))


# Rota para link de autorização
@app.route("/auth/github")
def auth_github():
    
    authorize_url = (
        "https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={GITHUB_REDIRECT_URI}&"
        "scope=read:user,repo"
    )

    return redirect(authorize_url)


# Rota para fazer a troca do código de autorização pelo token do github
@app.route("/github/callback")
def github_callback():
    #Codigo que o github envia de autorização
    code = request.args.get("code")

    if not code:
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Código de autorização não recebido.", 
                                code=400))

    # Construindo confirmação e troca do código pelo token
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    payload = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": GITHUB_REDIRECT_URI,
    }
    
    # Trocando código pelo token
    response = requests.post(token_url, headers=headers, data=payload)
    token_data = response.json()

    # TOKEN DE ACESSO
    access_token = token_data.get("access_token")

    if not access_token:
        print(f"Erro ao obter token: {token_data}")
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Não foi possível receber o token de acesso do Github", 
                                code=500))

    # Sucesso
    return redirect(url_for("auth_connection_response", message="Conta do Github conectada com sucesso!", code=200))



if __name__ == "__main__":
    app.run(debug=True)