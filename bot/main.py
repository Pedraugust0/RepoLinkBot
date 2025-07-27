import discord
from discord.ext import commands
from dotenv import load_dotenv
import os


load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")


intents = discord.Intents.default()

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    await bot.tree.sync()
    print(f"BOT coisado!")

@bot.tree.command(name="site", description="Envia o link do site")
async def site_command(interaction: discord.Interaction):
    await interaction.response.send_message("Link: https://github.com")

bot.run(TOKEN)