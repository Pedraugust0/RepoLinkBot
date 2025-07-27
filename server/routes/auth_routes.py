from flask import Blueprint, render_template, request

auth_bp = Blueprint('auth_bp', __name__)

# Endpoint de resposta da autenticação
@auth_bp.route("/auth/connection_response", methods=["GET"])
def auth_connection_response():
    message = request.args.get("message")
    code = request.args.get("code")

    return render_template("connection/connection_response.html",
                            message=message,
                            code=code)