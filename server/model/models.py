import peewee
import os
from dotenv import load_dotenv
import datetime
from utils.encryption import encrypt_data, decrypt_data

db = peewee.SqliteDatabase("database/banco.db")

load_dotenv()

ENCRYPTION_KEY = os.environ.get('APP_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("APP_ENCRYPTION_KEY not set in environment variables or .env file!")


class BaseModel(peewee.Model):
    class Meta:
        database = db

class User(BaseModel):
    username = peewee.CharField(unique=True) 
    password_hash = peewee.CharField()
    token_discord = peewee.CharField(null=True) 

    discord_user_id = peewee.BigIntegerField(null=True, unique=True)
    discord_notification_channel_id = peewee.BigIntegerField(null=True)
    token_trello = peewee.CharField(null=True)

    def __repr__(self):
        return f"<User: {self.username}>"

    def __str__(self):
        return self.username


class GitHubInstallation(BaseModel):
    user = peewee.ForeignKeyField(User, backref='github_installations', null=True)
    
    installation_id = peewee.IntegerField(unique=True, index=True)
    encrypted_access_token = peewee.TextField()
    expires_at = peewee.DateTimeField()
    
    github_account_login = peewee.CharField(null=True)
    github_account_id = peewee.IntegerField(null=True)
    github_account_type = peewee.CharField(null=True)

    class Meta:
        database = db
        indexes = (
            (('user', 'installation_id'), True),
        )

    def save_encrypted_token(self, token_value: str, expires_at: datetime.datetime):
        self.encrypted_access_token = encrypt_data(token_value).decode('utf-8')
        self.expires_at = expires_at
        self.save()

    def get_decrypted_token(self) -> str:
        if self.encrypted_access_token:
            return decrypt_data(self.encrypted_access_token.encode('utf-8'))
        return None


class StatusMessage:
    def __init__(self, message=None, log_message=None, code=None, is_error=False):
        self.message = message
        self.log_message = log_message
        self.code = code
        self.is_error = is_error
    
    def __str__(self):
        return f"{self.message}"