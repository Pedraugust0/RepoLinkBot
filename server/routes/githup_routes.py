from flask import Blueprint, session, redirect, flash, url_for, request, abort, jsonify
import hmac
from config import GITHUB_WEBHOOK_SECRET
import hashlib
import os
from utils.github_auth_service import get_installation_access_token, get_valid_github_installation_token
from utils.discord_notifier import send_discord_notification

from model.models import GitHubInstallation, User

github_bp = Blueprint('github_bp', __name__)

@github_bp.route('/github/webhook', methods=['POST'])
def github_webhook():
    
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        abort(400, description="Signature required")

    digest = hmac.new(GITHUB_WEBHOOK_SECRET, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(f'sha256={digest}', signature):
        abort(401, description="Invalid signature")

    event_type = request.headers.get('X-GitHub-Event')
    payload = request.json

    print(f"Webhook GitHub recebido: Evento '{event_type}'")

    if event_type == 'installation':
        installation_id = payload['installation']['id']
        action = payload['action']
        
        webhook_account_info = {
            'id': payload['installation']['account']['id'],
            'login': payload['installation']['account']['login'],
            'type': payload['installation']['account']['type']
        }
        
        user_associated = None 
        existing_install = GitHubInstallation.get_or_none(installation_id=installation_id)
        if existing_install and existing_install.user:
            user_associated = existing_install.user

        if action == 'created':
            print(f"Novo GitHub App instalado! Installation ID: {installation_id}")
            token = get_installation_access_token(
                installation_id, 
                user_obj=user_associated,
                github_account_info=webhook_account_info
            )
            print(f"Token de instalação obtido: {token[:10]}...")
            
            # TODO: 
        
        elif action == 'deleted':
            print(f"GitHub App desinstalado! Installation ID: {installation_id}")
            GitHubInstallation.delete().where(GitHubInstallation.installation_id == installation_id).execute()
            print(f"Dados da instalação {installation_id} removidos do DB.")

    elif event_type == 'installation_repositories':
        installation_id = payload['installation']['id']
        repositories_added = payload.get('repositories_added', [])
        repositories_removed = payload.get('repositories_removed', [])

        installation_obj = GitHubInstallation.get_or_none(installation_id=installation_id)
        user_for_token_renewal = installation_obj.user if installation_obj else None
        
        webhook_account_info_repo = {
            'id': payload['installation']['account']['id'],
            'login': payload['installation']['account']['login'],
            'type': payload['installation']['account']['type']
        }

        if repositories_added:
            print(f"Repositórios adicionados à instalação {installation_id}: {repositories_added}")
            token = get_valid_github_installation_token(
                installation_id, 
                user_obj=user_for_token_renewal, 
                github_account_info=webhook_account_info_repo
            )
            # TODO
            

        if repositories_removed:
            print(f"Repositórios removidos da instalação {installation_id}: {repositories_removed}")
            # TODO

    elif event_type == 'push':
        handle_push_event(payload)

    elif event_type == 'pull_request':
        action = payload['action']
        pr_title = payload['pull_request']['title']
        pr_url = payload['pull_request']['html_url']
        sender = payload['sender']['login']

        print(f"\n--- Evento PULL REQUEST recebido ---")
        print(f"Ação: {action}")
        print(f"Título do PR: '{pr_title}'")
        print(f"Autor do PR: {sender}")
        print(f"URL do PR: {pr_url}")

    elif event_type == 'commit_comment':
        comment_user = payload['comment']['user']['login']
        repository_full_name = payload['repository']['full_name']
        comment_body = payload['comment']['body']
        comment_url = payload['comment']['html_url']
        commit_sha = payload['comment']['commit_id']
        
        print(f"\n--- Evento COMMIT COMMENT recebido ---")
        print(f"Comentário de: {comment_user}")
        print(f"No repositório: {repository_full_name}")
        print(f"No commit (SHA): {commit_sha[:7]}")
        print(f"Conteúdo do Comentário: {comment_body}")
        print(f"URL do Comentário: {comment_url}")
        
        # TODO


    else:
        print(f"Evento GitHub '{event_type}' não tratado.")

    return jsonify({'status': 'success', 'event': event_type}), 200

def handle_push_event(payload):
    try:
        repo_name = payload['repository']['full_name']
        pusher_name = payload['pusher']['name']
        branch = payload['ref'].split('/')[-1]

        head_commit = payload.get('head_commit')
        if not head_commit:
            print("Evento de push ignorado (sem head_commit, ex: branch deletada).")
            return

        commit_message = head_commit['message']
        commit_url = head_commit['url']

        installation_id = payload['installation']['id']
        installation = GitHubInstallation.get_or_none(GitHubInstallation.installation_id == installation_id)

        if not installation or not installation.user:
            print(f"Notificação de push ignorada: Instalação {installation_id} não está associada a um usuário no sistema.")
            return

        user = installation.user
        notification_channel_id = user.discord_notification_channel_id
        if not notification_channel_id:
            print(f"Notificação de push ignorada: Usuário {user.username} não possui um canal de notificação configurado.")
            return

        message = (
            f"**:rocket: Push recebido - {pusher_name}**\n\n"
            f"**Repositório:** `{repo_name}`\n"
            f"**Branch:** `{branch}`\n"
            f"**Mensagem do commit:**\n"
            f"```\n{commit_message}\n```\n"
            f"**Link do commit:** <{commit_url}>"
        )
        send_discord_notification(str(notification_channel_id), message)

    except Exception as e:
        print(f"ERRO ao processar evento de push: {e}")

@github_bp.route("/github/install")
def github_install():
    if "user_id" not in session:
        flash("Você precisa estar logado para conectar seu GitHub.", "warning")
        return redirect(url_for('login'))
    
    user = User.get_by_id(session['user_id'])
    
    state = os.urandom(16).hex()
    session['github_oauth_state'] = state
    session['github_install_user_id'] = user.id

    GITHUB_APP_SLUG = os.getenv("GITHUB_APP_SLUG")
    if not GITHUB_APP_SLUG:
        flash("GITHUB_APP_SLUG não configurado no ambiente.", "danger")
        print("")
        return redirect(url_for('choose_manager'))

    install_url = (
        f"https://github.com/apps/{GITHUB_APP_SLUG}/installations/new"
        f"?state={state}"
    )
    
    return redirect(install_url)


@github_bp.route("/github/callback")
def github_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    installation_id = request.args.get('installation_id')
    setup_action = request.args.get('setup_action')
    
    account_id = request.args.get('account_id')
    account_login = request.args.get('account_login')
    account_type = request.args.get('account_type')

    expected_state = session.pop('github_oauth_state', None)
    user_id_from_session = session.pop('github_install_user_id', None)

    if not state or state != expected_state:
        flash("Erro de segurança: State inválido ou ausente.", "danger")
        return redirect(url_for('choose_manager'))

    if not user_id_from_session:
        flash("Sessão de usuário perdida. Por favor, faça login novamente.", "danger")
        return redirect(url_for('login'))
    
    user = User.get_by_id(user_id_from_session)

    if setup_action == 'install' and installation_id:
        flash(f"GitHub App instalado com sucesso na conta {account_login}!", "success")
        print(f"Installation ID recebido no callback: {installation_id}")

        github_account_info = {
            'id': account_id,
            'login': account_login,
            'type': account_type
        }
        
        try:
            get_installation_access_token(installation_id, user_obj=user, github_account_info=github_account_info)
            flash("Conexão com GitHub App estabelecida e token salvo.", "success")
        except Exception as e:
            flash(f"Erro ao obter ou salvar token do GitHub App: {e}", "danger")
            print(f"Erro ao processar instalação/token: {e}")
            return redirect(url_for('choose_manager'))

    elif setup_action == 'update' and installation_id:
        flash(f"GitHub App configurado novamente para a conta {account_login}.", "info")
        print(f"Configuração de instalação atualizada para ID: {installation_id}")
        
        try:
            installation_obj, created = GitHubInstallation.get_or_create(
                installation_id=installation_id,
                defaults={'user': user, 'github_account_login': account_login, 'github_account_id': account_id, 'github_account_type': account_type}
            )
            if not created:
                installation_obj.user = user
                installation_obj.github_account_login = account_login
                installation_obj.github_account_id = account_id
                installation_obj.github_account_type = account_type
                installation_obj.save()
            
            get_valid_github_installation_token(installation_id, user_obj=user)
            flash("Conexão com GitHub App atualizada.", "success")
        except Exception as e:
            flash(f"Erro ao atualizar token ou informações do GitHub App: {e}", "danger")
            print(f"Erro ao processar atualização: {e}")
            return redirect(url_for('choose_manager'))

    else:
        flash("Instalação ou configuração do GitHub App não foi concluída.", "info")

    return redirect(url_for('choose_manager'))