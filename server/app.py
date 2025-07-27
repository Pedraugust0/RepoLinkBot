from flask import Flask, request, render_template, url_for, redirect
import peewee
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask("__name__")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = "http://127.0.0.1:5000/github/callback"

DISCORD_CLIENT_ID= os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET= os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI= "http://127.0.0.1:5000/discord/callback"

@app.route("/", methods=["GET"])
def home():
    return render_template("main/home.html")

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
        return redirect(url_for("connection/connection_response.html", 
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
        return redirect(url_for("connection/connection_response.html", 
                               message="Erro: Não foi possível receber o token de acesso do Github", 
                               code=500))

    # Sucesso
    return redirect(url_for("auth_connection_response", message="Conta do Github conectada com sucesso!", code=200))



if __name__ == "__main__":
    app.run(debug=True)
