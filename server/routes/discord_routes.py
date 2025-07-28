from flask import Blueprint, redirect, request, url_for, session, jsonify # Adicionar session e jsonify
import requests
from model.models import User
from peewee import IntegrityError
from config import DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI

discord_bp = Blueprint('discord_bp', __name__)

@discord_bp.route("/auth/discord")
def auth_discord():
    if "user_id" not in session:
        return "Erro: Você precisa estar logado para conectar sua conta.", 401

    authorize_url = (
        "https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={DISCORD_REDIRECT_URI}&"
        "response_type=code&"
        r"scope=identify%20guilds"
    )

    return redirect(authorize_url)


@discord_bp.route("/discord/callback")
def discord_callback():
    if "user_id" not in session:
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Sessão de usuário expirada. Por favor, faça login novamente.", 
                                code=401))

    code = request.args.get("code")
    if not code:
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Código de autorização não recebido.", 
                                code=400))
    
    token_url = "https://discord.com/api/oauth2/token"
    payload = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(url=token_url, data=payload, headers=headers)
    
    if token_response.status_code != 200:
        print(f"Erro ao obter token do Discord: {token_response.text}")
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Falha ao obter token de acesso do Discord.", 
                                code=500))

    tokens_data = token_response.json()
    access_token = tokens_data.get("access_token")

    user_info_url = "https://discord.com/api/v10/users/@me"
    user_info_headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(user_info_url, headers=user_info_headers)

    if user_info_response.status_code != 200:
        return redirect(url_for("auth_connection_response", 
                                message="Erro: Falha ao obter informações do usuário do Discord.", 
                                code=500))

    discord_user_data = user_info_response.json()
    discord_user_id = discord_user_data.get("id")

    try:
        user = User.get_by_id(session["user_id"])
        user.discord_user_id = discord_user_id
        user.save()
    except IntegrityError:
        print(f"Tentativa de vincular um Discord ID ({discord_user_id}) que já está em uso.")
        return redirect(url_for("auth_connection_response",
                                message="Erro: Esta conta do Discord já está vinculada a outro usuário.",
                                code=409))
    except Exception as e:
        print(f"Erro ao salvar dados do Discord no DB: {e}")
        return redirect(url_for("auth_connection_response", message="Erro: Falha ao vincular conta no banco de dados.", code=500))

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