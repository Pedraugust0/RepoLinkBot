import requests
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")

def send_discord_notification(channel_id: str, message_content: str):
    if not TOKEN:
        print("ERRO CRÍTICO: A variável de ambiente DISCORD_TOKEN não está configurada no servidor.")
        return

    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {TOKEN}",
        "Content-Type": "application/json"
    }
    payload = { "content": message_content }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Notificação enviada com sucesso para o canal {channel_id}")
    except requests.exceptions.RequestException as e:
        print(f"Falha ao enviar notificação para o canal {channel_id}: {e}")