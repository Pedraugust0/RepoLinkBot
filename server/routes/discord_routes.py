from flask import Blueprint, redirect, request, url_for, jsonify
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

@discord_bp.route('/api/discord/setup', methods=['POST'])
def setup_discord_channel():
    data = request.get_json()
    if not data or 'discord_user_id' not in data or 'channel_id' not in data:
        return jsonify({"error": "Dados incompletos. Faltando 'discord_user_id' ou 'channel_id'."}), 400

    discord_user_id = data['discord_user_id']
    channel_id = data['channel_id']

    user = User.get_or_none(User.discord_user_id == discord_user_id)

    if not user:
        return jsonify({"error": "Usuário do Discord não encontrado. Por favor, conecte sua conta no nosso site primeiro."}), 404

    try:
        user.discord_notification_channel_id = int(channel_id)
        user.save()
        print(f"Canal de notificação {channel_id} salvo para o usuário {user.username} (Discord ID: {discord_user_id})")
        return jsonify({"message": "Canal configurado com sucesso!"}), 200
    except Exception as e:
        print(f"Erro ao salvar o canal de notificação no DB: {e}")
        return jsonify({"error": "Erro interno do servidor ao salvar a configuração."}), 500