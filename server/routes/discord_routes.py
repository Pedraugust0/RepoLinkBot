from flask import Blueprint, redirect, request, url_for
import requests
from model.models import GitHubInstallation, User
import os
from dotenv import load_dotenv
from config import DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI

discord_bp = Blueprint('discord_bp', __name__)

# Rota para link de autorização
@discord_bp.route("/auth/discord")
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
@discord_bp.route("/discord/callback")
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