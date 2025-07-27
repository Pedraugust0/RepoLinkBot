import os
from dotenv import load_dotenv

load_dotenv()


# Dados do App e Webhook
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET').encode('utf-8')

with open(os.getenv("GITHUB_PRIVATE_KEY_PATH"), 'rb') as key_file:
    GITHUB_PRIVATE_KEY = key_file.read()

# Endpoint para pegar token
GITHUB_REDIRECT_URI = "http://127.0.0.1:5000/github/callback"

# Dados do OAuth2 do Discord
DISCORD_CLIENT_ID= os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET= os.getenv("DISCORD_CLIENT_SECRET")
# Endpoint para pegar token
DISCORD_REDIRECT_URI= "http://127.0.0.1:5000/discord/callback"

ENCRYPTION_KEY = os.environ.get('APP_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("APP_ENCRYPTION_KEY not set in environment variables or .env file!")