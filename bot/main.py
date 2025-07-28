import discord
from discord.ext import commands
from dotenv import load_dotenv
import os
import requests

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:5000")

intents = discord.Intents.default()

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"BOT coisado!")

@bot.tree.command(name="setup", description="Configurar ambiente do bot")
async def setup_comand(interaction: discord.Interaction):
    guild = interaction.guild
    channel_name = f"notificacoes-{interaction.user.name.lower()}"

    await interaction.response.defer(ephemeral=True)

    existing_channel = discord.utils.get(guild.channels, name=channel_name)

    if existing_channel:
        await interaction.followup.send(f"O canal de notificações '{channel_name}' já existe!")
        return

    new_channel = await guild.create_text_channel(channel_name)

    api_url = f"{API_BASE_URL}/api/discord/setup"
    payload = {
        "discord_user_id": str(interaction.user.id),
        "channel_id": str(new_channel.id)
    }

    try:
        response = requests.post(api_url, json=payload)

        if response.status_code == 200:
            await new_channel.send(f"Olá {interaction.user.mention}! Usarei este canal para enviar as notificações do GitHub.")
            await interaction.followup.send(f"Canal `#{channel_name}` criado e configurado com sucesso!")
        else:
            error_message = response.json().get('error', 'Ocorreu um erro desconhecido no servidor.')
            await interaction.followup.send(f"Falha ao configurar o canal no servidor: {error_message}. Por favor, verifique se você conectou sua conta Discord no site. O canal será deletado.")
            await new_channel.delete()

    except requests.exceptions.RequestException as e:
        await interaction.followup.send(f"Não foi possível conectar ao servidor para configurar o canal. Por favor, tente novamente mais tarde. O canal será deletado.")
        await new_channel.delete()
        print(f"Erro de conexão com a API: {e}")


@bot.tree.command(name="site", description="Envia o link do site")
async def site_command(interaction: discord.Interaction):
    site_url = os.getenv("SITE_URL", "http://127.0.0.1:5000")
    await interaction.response.send_message(f"Link do site: {site_url}")

bot.run(TOKEN)