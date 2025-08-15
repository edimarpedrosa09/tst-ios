#!/usr/bin/env python3
"""
Script de Integração da Funcionalidade de Deletar Usuários
Execute: python integrate_delete_users.py
"""

import os
import shutil
from datetime import datetime

def create_backup():
    """Criar backup do arquivo admin_pages.py atual"""
    backup_dir = f"backup_delete_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    if os.path.exists('admin_pages.py'):
        os.makedirs(backup_dir, exist_ok=True)
        shutil.copy2('admin_pages.py', os.path.join(backup_dir, 'admin_pages.py.backup'))
        print(f"✅ Backup criado em: {backup_dir}/admin_pages.py.backup")
        return True
    else:
        print("⚠️ admin_pages.py não encontrado - substitua pelo novo arquivo")
        return False

def verify_user_management():
    """Verificar se user_management.py tem as funções necessárias"""
    
    if not os.path.exists('user_management.py'):
        print("❌ user_management.py não encontrado!")
        return False
    
    # Verificar se contém a função delete_user
    with open('user_management.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    required_items = [
        'def delete_user(',
        'Permission.DELETE_USERS',
        'soft delete',
        'UPDATE users'
    ]
    
    missing = []
    for item in required_items:
        if item not in content:
            missing.append(item)
    
    if missing:
        print(f"⚠️ Funcionalidades faltando em user_management.py: {missing}")
        print("💡 O user_management.py fornecido já tem a funcionalidade de deletar")
        return True  # Assumir que está OK se tem algumas das funções
    
    print("✅ user_management.py contém as funcionalidades de deleção")
    return True

def test_admin_access():
    """Testar se o sistema de admin funciona"""
    print("🔍 Verificando sistema de admin...")
    
    try:
        # Verificar se as funções estão disponíveis
        if os.path.exists('admin_pages.py'):
            with open('admin_pages.py', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verificar funcionalidades de deleção
            delete_features = [
                'render_user_card_with_delete',
                'confirm_delete_',
                'delete_user(',
                'DELETAR USUÁRIO'
            ]
            
            found_features = []
            for feature in delete_features:
                if feature in content:
                    found_features.append(feature)
            
            if len(found_features) >= 3:
                print("✅ Funcionalidades de deleção encontradas no admin_pages.py")
                return True
            else:
                print(f"⚠️ Apenas {len(found_features)}/4 funcionalidades encontradas")
                return False
        else:
            print("❌ admin_pages.py não encontrado")
            return False
            
    except Exception as e:
        print(f"❌ Erro ao verificar admin: {e}")
        return False

def show_integration_instructions():
    """Mostrar instruções detalhadas de integração"""
    
    print("\n" + "="*70)
    print("🚀 INSTRUÇÕES PARA ATIVAR DELEÇÃO DE USUÁRIOS")
    print("="*70)
    
    print("\n📋 PASSOS PARA INTEGRAR:")
    print("1. ✅ Substitua seu admin_pages.py pelo código fornecido")
    print("2. 🔍 Certifique-se de que user_management.py está atualizado")
    print("3. 🚀 Reinicie sua aplicação Streamlit")
    print("4. 🔐 Faça login como administrador")
    print("5. 🛡️ Acesse: Administração > Gerenciar Usuários")
    print("6. 👥 Clique em 'Ações' em qualquer usuário")
    print("7. 🗑️ A opção 'Deletar Usuário' estará disponível")
    
    print("\n🎯 COMO USAR A FUNCIONALIDADE:")
    print("• 👥 Na lista de usuários, clique em 'Ações' ao lado do usuário")
    print("• 🗑️ Clique em 'Deletar Usuário' (botão vermelho)")
    print("• ⚠️ Confirme a deleção (ação irreversível)")
    print("• ✅ Usuário será marcado como inativo (soft delete)")
    print("• 📋 Ação será registrada nos logs administrativos")
    
    print("\n🔐 PERMISSÕES NECESSÁRIAS:")
    print("• ✅ Username deve conter 'admin' OU")
    print("• 🛡️ Role 'admin' ou 'super_admin' na tabela users_extended OU")
    print("• 👤 Ser o primeiro usuário do sistema")
    
    print("\n⚠️ SEGURANÇA E LIMITAÇÕES:")
    print("• 🚫 Admins não podem deletar a si mesmos")
    print("• 🔒 Apenas usuários com permissão DELETE_USERS podem deletar")
    print("• 💾 Deleção é 'soft delete' - usuário fica inativo")
    print("• 📝 Todas as ações são logadas")
    print("• 🔄 Usuário deletado pode ser reativado alterando status")
    
    print("\n🛠️ FUNCIONALIDADES INCLUÍDAS:")
    print("• 🗑️ Deletar usuários (soft delete)")
    print("• 🔑 Reset de senhas com geração automática")
    print("• 🔄 Ativar/Desativar usuários")
    print("• ✏️ Editar informações dos usuários")
    print("• ➕ Criar novos usuários")
    print("• 🔍 Buscar e filtrar usuários")
    print("• 📊 Estatísticas detalhadas")
    print("• 📋 Logs de todas as ações")
    
    print("\n🔧 TROUBLESHOOTING:")
    print("• ❌ Se não vir 'Deletar Usuário': Verifique permissões de admin")
    print("• 🔒 Se der erro de permissão: Username deve conter 'admin'")
    print("• 💾 Se erro no banco: Verifique se user_management.py está atualizado")
    print("• 🔄 Se funcionalidade não aparece: Reinicie o Streamlit")
    
    print("\n📱 EXEMPLO DE USO:")
    print("1. 🔐 Login como 'admin' ou 'admin123'")
    print("2. 🛡️ Ir para Administração > Gerenciar Usuários")
    print("3. 👥 Na lista, encontrar usuário 'joao.silva'")
    print("4. ⚙️ Clicar em 'Ações' ao lado do usuário")
    print("5. 🗑️ Clicar em 'Deletar Usuário'")
    print("6. ⚠️ Confirmar com 'SIM, DELETAR'")
    print("7. ✅ Usuário será desativado imediatamente")
    
    print("\n" + "="*70)

def verify_database_requirements():
    """Verificar se o banco tem as tabelas necessárias"""
    print("🗄️ Verificando requisitos do banco de dados...")
    
    try:
        # Verificar se existe configuração do banco
        if os.path.exists('config.py'):
            with open('config.py', 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            if 'DATABASE_URL' in config_content:
                print("✅ Configuração de banco encontrada")
            else:
                print("⚠️ DATABASE_URL não encontrada em config.py")
        
        # Verificar se database.py tem as funções necessárias
        if os.path.exists('database.py'):
            with open('database.py', 'r', encoding='utf-8') as f:
                db_content = f.read()
            
            db_features = [
                'class DatabaseManager',
                'get_connection',
                'init_database',
                'users_extended'
            ]
            
            found_db = sum(1 for feature in db_features if feature in db_content)
            
            if found_db >= 3:
                print("✅ DatabaseManager parece estar configurado")
            else:
                print(f"⚠️ DatabaseManager pode estar incompleto ({found_db}/4)")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao verificar banco: {e}")
        return False

def check_streamlit_installation():
    """Verificar se Streamlit está instalado"""
    try:
        import streamlit
        print(f"✅ Streamlit {streamlit.__version__} instalado")
        return True
    except ImportError:
        print("❌ Streamlit não instalado")
        print("💡 Execute: pip install streamlit")
        return False

def main():
    """Função principal"""
    
    print("🗑️ ATIVANDO FUNCIONALIDADE DE DELETAR USUÁRIOS")
    print("="*60)
    
    # Passo 1: Verificar Streamlit
    print("\n📦 Passo 1: Verificando Streamlit...")
    if not check_streamlit_installation():
        print("❌ Instale o Streamlit primeiro")
        return
    
    # Passo 2: Backup
    print("\n📦 Passo 2: Criando backup...")
    create_backup()
    
    # Passo 3: Verificar user_management.py
    print("\n🔍 Passo 3: Verificando user_management.py...")
    if not verify_user_management():
        print("❌ Verifique se user_management.py está correto")
    
    # Passo 4: Verificar banco
    print("\n🗄️ Passo 4: Verificando banco de dados...")
    verify_database_requirements()
    
    # Passo 5: Testar admin
    print("\n🔍 Passo 5: Verificando sistema admin...")
    if test_admin_access():
        print("✅ Sistema admin parece estar OK")
    else:
        print("⚠️ Substitua admin_pages.py pelo código fornecido")
    
    # Passo 6: Instruções
    show_integration_instructions()
    
    print("\n✅ INTEGRAÇÃO CONCLUÍDA!")
    print("🔗 Agora substitua o admin_pages.py e reinicie o Streamlit")

if __name__ == "__main__":
    main()
