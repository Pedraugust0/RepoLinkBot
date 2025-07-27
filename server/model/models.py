import peewee

db = peewee.SqliteDatabase("database/banco.db")

class BaseModel(peewee.Model):
    class Meta:
        database = db

class User(BaseModel):
    username = peewee.CharField()
    password_hash = peewee.CharField()
    token_discord = peewee.CharField(null=True)
    token_github = peewee.CharField(null=True)
    token_trello = peewee.CharField(null=True)


    def __repr__(self):
        return f"<User: {self.username}>"

    def __str__(self):
        return self.username

class Error:
    
    def __init__(self, message=None, code=None):
        self.message = message
        self.code = code
    
    def __str__(self):
        return f"{self.message} {self.code}"