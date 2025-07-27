from flask import Blueprint, session, redirect, flash, url_for, request
import os
from utils.github_auth_service import get_installation_access_token, get_valid_github_installation_token
from model.models import GitHubInstallation, User

github_bp = Blueprint('github_bp', __name__)

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