from flask import Blueprint, jsonify
from model.models import GitHubInstallation, User

api_bp = Blueprint('api_bp', __name__)

@api_bp.route("/api/user", methods=["GET"])
def get_users():
    users_data = []
    for user in User.select():
        user_installations = []
        for installation in user.github_installations: # Acessa as instalações via backref
            decrypted_token = installation.get_decrypted_token()
            user_installations.append({
                "installation_id": installation.installation_id,
                "github_account_login": installation.github_account_login,
                "github_account_type": installation.github_account_type,
                "access_token_preview": decrypted_token[:10] + "..." if decrypted_token else "N/A",
                "expires_at": installation.expires_at.isoformat() if installation.expires_at else None
            })
        
        users_data.append({
            "id": user.id,
            "username": user.username,
            "github_installations": user_installations
        })
    
    return jsonify(users_data)

@api_bp.route("/api/installation")
def get_installations():
    installations_data = []
    for installation in GitHubInstallation.select():
        decrypted_token = installation.get_decrypted_token()
        installations_data.append({
            "installation_id": installation.installation_id,
            "user_id": installation.user.id if installation.user else None, # ID do usuário do seu sistema
            "username": installation.user.username if installation.user else None, # Username do usuário do seu sistema
            "github_account_login": installation.github_account_login,
            "github_account_type": installation.github_account_type,
            "access_token_preview": decrypted_token[:10] + "..." if decrypted_token else "N/A",
            "expires_at": installation.expires_at.isoformat() if installation.expires_at else None
        })
    
    return jsonify(installations_data)

