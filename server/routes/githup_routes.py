from flask import Blueprint, session, redirect, flash, url_for, request, abort, jsonify
import hmac
from config import GITHUB_WEBHOOK_SECRET
import hashlib
import os
from utils.github_auth_service import get_installation_access_token, get_valid_github_installation_token
from model.models import GitHubInstallation, User

github_bp = Blueprint('github_bp', __name__)

@github_bp.route('/github/webhook', methods=['POST']) # Exemplo se estiver no app.py
def github_webhook():
    
    # 1. Verificar a assinatura do webhook (segurança)
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        # Se não houver assinatura, a requisição é inválida
        abort(400, description="Signature required")

    # O GITHUB_WEBHOOK_SECRET_BYTES deve ser um objeto bytes.
    # Certifique-se de que ele está corretamente carregado e codificado.
    digest = hmac.new(GITHUB_WEBHOOK_SECRET, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(f'sha256={digest}', signature):
        # Se as assinaturas não correspondem, a requisição não é autêntica
        abort(401, description="Invalid signature")


    # 2. Pega o conteúdo do evento
    event_type = request.headers.get('X-GitHub-Event')
    payload = request.json

    print(f"Webhook GitHub recebido: Evento '{event_type}'")

    # 3. Processar eventos com base no tipo dele
    if event_type == 'installation':
        installation_id = payload['installation']['id']
        action = payload['action']
        
        # Informações da conta GitHub (usuário ou organização) que instalou/desinstalou o App
        webhook_account_info = {
            'id': payload['installation']['account']['id'],
            'login': payload['installation']['account']['login'],
            'type': payload['installation']['account']['type']
        }
        
        # Tenta associar o webhook a um usuário do seu sistema.
        # No webhook, não temos o user_id da sessão Flask.
        # A associação principal user-installation_id é feita no callback do GitHub App.
        # Aqui, tentamos recuperar o usuário associado se a instalação já existir no DB.
        user_associated = None 
        existing_install = GitHubInstallation.get_or_none(installation_id=installation_id)
        if existing_install and existing_install.user:
            user_associated = existing_install.user

        if action == 'created':
            print(f"Novo GitHub App instalado! Installation ID: {installation_id}")
            # Quando o App é instalado, você obtém o primeiro token de instalação.
            # get_installation_access_token também salva/atualiza o registro no DB.
            token = get_installation_access_token(
                installation_id, 
                user_obj=user_associated, # Passa o usuário associado (se encontrado)
                github_account_info=webhook_account_info # Passa informações da conta GitHub
            )
            print(f"Token de instalação obtido: {token[:10]}...") # Imprime os primeiros 10 caracteres
            
            # TODO: Aqui você adicionaria a lógica para configurar webhooks adicionais
            # nos repositórios que foram selecionados durante a instalação.
            # Os repositórios selecionados estão em payload['repositories'] para o evento 'installation:created'.
            # Exemplo: create_repo_webhooks(installation_id, token, payload['repositories'])

        elif action == 'deleted':
            print(f"GitHub App desinstalado! Installation ID: {installation_id}")
            # Limpa os dados relacionados a esta instalação do seu banco de dados.
            GitHubInstallation.delete().where(GitHubInstallation.installation_id == installation_id).execute()
            print(f"Dados da instalação {installation_id} removidos do DB.")
            # Opcional: flash("Conexão com GitHub App removida.", "info") - se esta rota puder renderizar flash messages

    elif event_type == 'installation_repositories':
        # Este evento ocorre quando o acesso do App a repositórios é alterado (adicionado/removido)
        installation_id = payload['installation']['id']
        repositories_added = payload.get('repositories_added', [])
        repositories_removed = payload.get('repositories_removed', [])

        # Tenta obter o objeto de instalação e o usuário associado para renovação/atualização do token.
        installation_obj = GitHubInstallation.get_or_none(installation_id=installation_id)
        user_for_token_renewal = installation_obj.user if installation_obj else None
        
        # Informações da conta GitHub do webhook (útil para atualização no DB se necessário)
        webhook_account_info_repo = {
            'id': payload['installation']['account']['id'],
            'login': payload['installation']['account']['login'],
            'type': payload['installation']['account']['type']
        }

        if repositories_added:
            print(f"Repositórios adicionados à instalação {installation_id}: {repositories_added}")
            # Obtém um token válido (renovará se necessário) para interagir com os novos repositórios.
            token = get_valid_github_installation_token(
                installation_id, 
                user_obj=user_for_token_renewal, 
                github_account_info=webhook_account_info_repo
            )
            # TODO: Lógica para configurar webhooks nos repositórios recém-adicionados.
            # Exemplo: create_repo_webhooks(installation_id, token, repositories_added)

        if repositories_removed:
            print(f"Repositórios removidos da instalação {installation_id}: {repositories_removed}")
            # TODO: Lógica para limpar webhooks ou permissões para esses repositórios no seu sistema.

    elif event_type == 'push':
        # Evento de 'push' ocorre quando novos commits são enviados para o repositório.
        repository_full_name = payload['repository']['full_name']
        pusher_name = payload['pusher']['name']
        ref = payload['ref'] # Ex: 'refs/heads/main' para a branch main

        print(f"\n--- Evento PUSH recebido ---")
        print(f"Repositório: {repository_full_name}")
        print(f"Autor do Push: {pusher_name}")
        print(f"Referência (Branch/Tag): {ref}")

        # O payload 'push' contém uma lista de commits. 'head_commit' é o commit mais recente.
        head_commit = payload.get('head_commit')

        if head_commit:
            commit_id = head_commit['id'] # O SHA do commit
            commit_message = head_commit['message']
            commit_author_name = head_commit['author']['name']
            commit_author_email = head_commit['author']['email']
            commit_url = head_commit['url'] # URL para o commit no GitHub

            print(f"  Último Commit (ID: {commit_id[:7]}):") # Imprime os 7 primeiros caracteres do SHA
            print(f"    Mensagem: {commit_message.strip()}") # .strip() para remover espaços/quebras de linha extras
            print(f"    Autor: {commit_author_name} <{commit_author_email}>")
            print(f"    URL: {commit_url}")
        else:
            print("  Nenhum commit principal encontrado no push (ex: branch deletada).")

        # TODO: Lógica para enviar notificação de Push para o Discord ou outro serviço.
        # Exemplo: send_push_notification(repository_full_name, pusher_name, head_commit_message)

    elif event_type == 'pull_request':
        # Evento de 'pull_request' ocorre quando um PR é aberto, fechado, atualizado, etc.
        action = payload['action']
        pr_title = payload['pull_request']['title']
        pr_url = payload['pull_request']['html_url']
        sender = payload['sender']['login']

        print(f"\n--- Evento PULL REQUEST recebido ---")
        print(f"Ação: {action}")
        print(f"Título do PR: '{pr_title}'")
        print(f"Autor do PR: {sender}")
        print(f"URL do PR: {pr_url}")
        
        # TODO: Lógica para enviar notificação de Pull Request para o Discord.
        # Exemplo: send_pull_request_notification(action, pr_title, sender, pr_url)

    elif event_type == 'commit_comment':
        # Evento de 'commit_comment' ocorre quando um comentário é feito em um commit.
        comment_user = payload['comment']['user']['login']
        repository_full_name = payload['repository']['full_name']
        comment_body = payload['comment']['body']
        comment_url = payload['comment']['html_url']
        commit_sha = payload['comment']['commit_id'] # ID do commit ao qual o comentário pertence
        
        print(f"\n--- Evento COMMIT COMMENT recebido ---")
        print(f"Comentário de: {comment_user}")
        print(f"No repositório: {repository_full_name}")
        print(f"No commit (SHA): {commit_sha[:7]}")
        print(f"Conteúdo do Comentário: {comment_body}")
        print(f"URL do Comentário: {comment_url}")
        
        # TODO: Lógica para enviar notificação de Comentário de Commit para o Discord.
        # Exemplo: send_commit_comment_notification(comment_user, repository_full_name, commit_sha, comment_body, comment_url)

    else:
        print(f"Evento GitHub '{event_type}' não tratado.")
    
    # 4. Retornar um status 200 OK para o GitHub
    # É crucial retornar 200 OK rapidamente para evitar que o GitHub re-envie o webhook.
    return jsonify({'status': 'success', 'event': event_type}), 200

@github_bp.route("/github/install")
def github_install():
    if "user_id" not in session:
        flash("Você precisa estar logado para conectar seu GitHub.", "warning")
        return redirect(url_for('login'))
    
    user = User.get_by_id(session['user_id'])
    
    # Gerar um 'state' único para evitar ataques CSRF e associar o redirecionamento ao usuário
    # Use algo mais robusto para produção, como um UUID ou uma string criptográfica aleatória
    state = os.urandom(16).hex() # Gera um token aleatório como state
    session['github_oauth_state'] = state # Armazena na sessão do Flask para verificação futura
    session['github_install_user_id'] = user.id # Armazena o ID do usuário que iniciou a instalação

    # URL para instalar o GitHub App
    # O GITHUB_APP_SLUG é o nome curto do seu app, encontrado no Portal do Desenvolvedor (abaixo do nome completo)
    # Ex: para 'My Awesome App', o slug pode ser 'my-awesome-app'
    # Você precisará definir GITHUB_APP_SLUG nas suas variáveis de ambiente também.
    GITHUB_APP_SLUG = os.getenv("GITHUB_APP_SLUG")
    if not GITHUB_APP_SLUG:
        flash("GITHUB_APP_SLUG não configurado no ambiente.", "danger")
        print("")
        return redirect(url_for('choose_manager'))

    # A URL de instalação baseia-se no seu App ID ou slug
    # A maneira mais robusta é usar o slug, pois o ID pode mudar entre ambientes
    install_url = (
        f"https://github.com/apps/{GITHUB_APP_SLUG}/installations/new"
        f"?state={state}" # Passa o state para que o GitHub o retorne no callback
    )
    
    # Você pode opcionalmente passar repositories_url para pré-selecionar repos (não é o caso agora)
    # ou setup_action=update para gerenciar uma instalação existente

    return redirect(install_url)


@github_bp.route("/github/callback")
def github_callback():
    # O GitHub redireciona para cá após a instalação/configuração do App

    code = request.args.get('code') # Código OAuth2 (não usaremos diretamente para App Installation Token)
    state = request.args.get('state') # Nosso state para verificação
    
    # O GitHub também envia o installation_id diretamente para o callback quando é uma nova instalação ou update
    installation_id = request.args.get('installation_id')
    
    # O setup_action indica se foi uma nova instalação ou atualização
    setup_action = request.args.get('setup_action')
    
    # Conta GitHub (usuário ou organização) que realizou a instalação
    # Estes parâmetros são enviados pelo GitHub na URL de callback
    account_id = request.args.get('account_id')
    account_login = request.args.get('account_login')
    account_type = request.args.get('account_type') # 'User' ou 'Organization'

    # 1. Verificar o 'state' para segurança (CSRF)
    expected_state = session.pop('github_oauth_state', None)
    user_id_from_session = session.pop('github_install_user_id', None)

    if not state or state != expected_state:
        flash("Erro de segurança: State inválido ou ausente.", "danger")
        return redirect(url_for('choose_manager'))

    if not user_id_from_session:
        flash("Sessão de usuário perdida. Por favor, faça login novamente.", "danger")
        return redirect(url_for('login'))
    
    user = User.get_by_id(user_id_from_session)

    # 2. Processar a instalação/configuração do App
    if setup_action == 'install' and installation_id:
        flash(f"GitHub App instalado com sucesso na conta {account_login}!", "success")
        print(f"Installation ID recebido no callback: {installation_id}")

        github_account_info = {
            'id': account_id,
            'login': account_login,
            'type': account_type
        }
        
        # Chamar get_installation_access_token para obter o token e salvar/atualizar no DB
        # Passamos o user_obj e as info da conta GitHub para associar e armazenar no DB
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
        
        # Se for uma atualização, o installation_id já deve existir no seu DB.
        # Você pode querer atualizar as permissões ou repositórios aqui,
        # e talvez renovar o token se necessário (get_valid_github_installation_token faz isso)
        try:
            # Garante que o objeto GitHubInstallation está associado ao User e atualizado
            installation_obj, created = GitHubInstallation.get_or_create(
                installation_id=installation_id,
                defaults={'user': user, 'github_account_login': account_login, 'github_account_id': account_id, 'github_account_type': account_type}
            )
            if not created: # Se não foi criado agora, atualiza
                installation_obj.user = user
                installation_obj.github_account_login = account_login
                installation_obj.github_account_id = account_id
                installation_obj.github_account_type = account_type
                installation_obj.save()
            
            # Tentar obter um token válido (isso renovará se necessário)
            get_valid_github_installation_token(installation_id, user_obj=user)
            flash("Conexão com GitHub App atualizada.", "success")
        except Exception as e:
            flash(f"Erro ao atualizar token ou informações do GitHub App: {e}", "danger")
            print(f"Erro ao processar atualização: {e}")
            return redirect(url_for('choose_manager'))

    else:
        # Se for qualquer outra coisa (ex: cancelou a instalação)
        flash("Instalação ou configuração do GitHub App não foi concluída.", "info")

    return redirect(url_for('choose_manager')) # Redireciona para sua página de gerenciamento