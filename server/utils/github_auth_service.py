import datetime
import jwt
import requests
from model.models import GitHubInstallation
from model.models import GitHubInstallation
from config import GITHUB_PRIVATE_KEY, GITHUB_APP_ID


# Funções para Gerar JWT e obter/renovar Installation Token
def generate_jwt():
    now = int(datetime.datetime.now().timestamp())
    payload = {
        'iat': now,
        'exp': now + (10 * 60), # Expira em 10 minutos (máx)
        'iss': GITHUB_APP_ID
    }
    return jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm='RS256')

def get_installation_access_token(installation_id, user_obj=None, github_account_info=None):
    jwt_token = generate_jwt()
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    response = requests.post(
        f'https://api.github.com/app/installations/{installation_id}/access_tokens',
        headers=headers
    )
    response.raise_for_status() # Lança HTTPError para respostas de erro (4xx ou 5xx)
    token_data = response.json()

    # Extrai informações do token
    new_token_value = token_data['token']
    new_expires_at = datetime.datetime.strptime(token_data['expires_at'], '%Y-%m-%dT%H:%M:%SZ')

    # O dicionário 'defaults' é usado apenas se um novo objeto for *criado*.
    # Se o objeto já existir, ele é retornado e os valores de 'defaults' são ignorados.
    # Certifique-se de que os campos obrigatórios tenham valores padrão aqui, mesmo que sejam vazios/temporários.
    # O `save_encrypted_token` os preencherá corretamente depois.
    defaults = {
        'encrypted_access_token': '', # Temporário, será sobrescrito
        'expires_at': datetime.datetime.now(), # Temporário, será sobrescrito
        'user': user_obj, # Vincula ao usuário que iniciou a instalação
        'github_account_login': github_account_info.get('login') if github_account_info else None,
        'github_account_id': github_account_info.get('id') if github_account_info else None,
        'github_account_type': github_account_info.get('type') if github_account_info else None,
    }

    # Use get_or_create para encontrar ou criar a instalação
    installation_obj, created = GitHubInstallation.get_or_create(
        installation_id=installation_id,
        defaults=defaults # Passa os valores padrão aqui
    )
    
    # Se o objeto já existia (not created), garanta que o usuário e informações da conta estejam atualizadas.
    # Isso é útil se a instalação foi feita via webhook primeiro e o user_obj não estava disponível,
    # ou se o usuário mudou as configurações.
    if not created:
        if user_obj and installation_obj.user != user_obj:
            installation_obj.user = user_obj
        if github_account_info:
            if installation_obj.github_account_login != github_account_info.get('login'):
                installation_obj.github_account_login = github_account_info.get('login')
            if installation_obj.github_account_id != github_account_info.get('id'):
                installation_obj.github_account_id = github_account_info.get('id')
            if installation_obj.github_account_type != github_account_info.get('type'):
                installation_obj.github_account_type = github_account_info.get('type')
            # Você pode adicionar um installation_obj.save() aqui se houver chances
            # dessas informações mudarem sem uma renovação de token.
            # No entanto, save_encrypted_token já chamará save().


    # Agora, use o método save_encrypted_token da instância para salvar o token e a expiração
    # Este método já cuida da criptografia e da atualização dos campos
    installation_obj.save_encrypted_token(new_token_value, new_expires_at)

    return new_token_value # Retorna o token descriptografado

# Função para obter um token válido (descriptografa e renova se necessário)
# Esta função também precisa receber o user_obj (e github_account_info opcionalmente)
def get_valid_github_installation_token(installation_id, user_obj=None, github_account_info=None):
    installation_obj = GitHubInstallation.get_or_none(installation_id=installation_id)
    
    if not installation_obj:
        print(f"Instalação {installation_id} não encontrada no DB. Tentando obter um novo token.")
        # Se não tem no DB, tentar obter um novo (primeira vez ou db perdido)
        # É CRUCIAL passar user_obj e github_account_info aqui para a criação
        return get_installation_access_token(installation_id, user_obj, github_account_info)

    # Descriptografa o token para verificar a validade
    current_token = installation_obj.get_decrypted_token()

    # Verifica se o token está expirado ou prestes a expirar (ex: nos próximos 5 minutos)
    # E garante que current_token não seja None (get_decrypted_token pode retornar None)
    if not current_token or installation_obj.expires_at < (datetime.datetime.now() + datetime.timedelta(minutes=5)):
        print(f"Token para instalação {installation_id} expirado ou prestes a expirar. Gerando novo...")
        # CRUCIAL: Passar user_obj e github_account_info para a renovação/atualização
        return get_installation_access_token(installation_id, user_obj, github_account_info)

    return current_token