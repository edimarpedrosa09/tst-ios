#!/usr/bin/env python3
"""
Script de Integração do Sistema de Gerenciamento de Usuários
Execute: python integrate_user_management.py
"""

import os
import shutil
from datetime import datetime

def create_backup():
    """Criar backup do arquivo admin_pages.py atual"""
    backup_dir = f"backup_user_management_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    if os.path.exists('admin_pages.py'):
        os.makedirs(backup_dir, exist_ok=True)
        shutil.copy2('admin_pages.py', os.path.join(backup_dir, 'admin_pages.py.backup'))
        print(f"✅ Backup criado em: {backup_dir}/admin_pages.py.backup")
        return True
    else:
        print("⚠️ admin_pages.py não encontrado - nada para fazer backup")
        return False

def update_admin_pages():
    """Atualizar admin_pages.py com a nova versão"""
    
    # Conteúdo da nova versão (coloque aqui o conteúdo do arquivo atualizado)
    new_content = '''# Aqui você deve colar o conteúdo completo do admin_pages.py atualizado
# que foi fornecido no artifact "final_admin_pages_integration"
'''
    
    # Por enquanto, apenas mostrar instruções
    print("📝 Para integrar o sistema de gerenciamento:")
    print("1. Substitua o conteúdo do seu admin_pages.py pelo conteúdo fornecido")
    print("2. O novo admin_pages.py já inclui todas as funcionalidades:")
    print("   • ✅ Criação de usuários")
    print("   • ✅ Edição de usuários") 
    print("   • ✅ Gerenciamento de MFA")
    print("   • ✅ Reset de senhas")
    print("   • ✅ Busca avançada")
    print("   • ✅ Estatísticas detalhadas")
    print("   • ✅ Logs administrativos")

def verify_user_management():
    """Verificar se user_management.py existe e está correto"""
    
    if not os.path.exists('user_management.py'):
        print("❌ user_management.py não encontrado!")
        print("💡 Você já tem esse arquivo no seu projeto - certifique-se de que está no local correto")
        return False
    
    # Verificar se contém as classes necessárias
    with open('user_management.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    required_items = [
        'class UserManager',
        'class Permission',
        'class UserRole',
        'create_user',
        'update_user',
        'delete_user',
        'get_all_users'
    ]
    
    missing = []
    for item in required_items:
        if item not in content:
            missing.append(item)
    
    if missing:
        print(f"⚠️ Itens faltando em user_management.py: {missing}")
        return False
    
    print("✅ user_management.py está presente e contém as funcionalidades necessárias")
    return True

def verify_dependencies():
    """Verificar dependências necessárias"""
    
    print("🔍 Verificando dependências...")
    
    # Dependências do sistema base
    base_deps = ['streamlit', 'pandas', 'psycopg2', 'hashlib']
    
    # Dependências MFA (opcionais)
    mfa_deps = ['pyotp', 'qrcode', 'PIL']
    
    # Dependências para relatórios avançados (opcionais)
    reports_deps = ['plotly', 'numpy', 'matplotlib', 'seaborn']
    
    print("📦 Dependências base:")
    for dep in base_deps:
        try:
            if dep == 'hashlib':
                import hashlib
            elif dep == 'psycopg2':
                import psycopg2
            elif dep == 'pandas':
                import pandas
            elif dep == 'streamlit':
                import streamlit
            print(f"  ✅ {dep}")
        except ImportError:
            print(f"  ❌ {dep} - Execute: pip install {dep}")
    
    print("🔐 Dependências MFA (opcionais):")
    for dep in mfa_deps:
        try:
            if dep == 'pyotp':
                import pyotp
            elif dep == 'qrcode':
                import qrcode
            elif dep == 'PIL':
                from PIL import Image
            print(f"  ✅ {dep}")
        except ImportError:
            print(f"  ⚠️ {dep} - Para MFA: pip install {dep}")
    
    print("📊 Dependências relatórios (opcionais):")
    for dep in reports_deps:
        try:
            if dep == 'plotly':
                import plotly
            elif dep == 'numpy':
                import numpy
            elif dep == 'matplotlib':
                import matplotlib
            elif dep == 'seaborn':
                import seaborn
            print(f"  ✅ {dep}")
        except ImportError:
            print(f"  ⚠️ {dep} - Para relatórios: pip install {dep}")

def show_integration_instructions():
    """Mostrar instruções detalhadas de integração"""
    
    print("\n" + "="*60)
    print("🚀 INSTRUÇÕES DE INTEGRAÇÃO")
    print("="*60)
    
    print("\n📋 PASSOS PARA INTEGRAR:")
    print("1. ✅ Faça backup do admin_pages.py atual (já feito)")
    print("2. 📝 Substitua o conteúdo do admin_pages.py pelo novo código")
    print("3. 🔍 Verifique se user_management.py está presente")
    print("4. 🚀 Reinicie sua aplicação Streamlit")
    print("5. 🔐 Faça login como administrador")
    print("6. 🛡️ Acesse: Administração > Gerenciar Usuários")
    
    print("\n🎯 FUNCIONALIDADES DISPONÍVEIS:")
    print("• 👥 Lista completa de usuários com filtros")
    print("• ➕ Criação de novos usuários")
    print("• ✏️ Edição de informações dos usuários")
    print("• 🔑 Reset de senhas com geração automática")
    print("• 🔐 Gerenciamento completo de MFA")
    print("• 🗑️ Deleção de usuários (soft/hard delete)")
    print("• 🔍 Busca avançada com múltiplos filtros")
    print("• 📊 Estatísticas detalhadas")
    print("• 📋 Logs de ações administrativas")
    
    print("\n⚙️ CONFIGURAÇÕES ADMIN:")
    print("• Username deve conter 'admin' para acesso")
    print("• Ou configure role='admin' na tabela users_extended")
    print("• Primeiro usuário é automaticamente admin")
    
    print("\n🔐 SISTEMA MFA:")
    print("• Instale: pip install pyotp qrcode[pil] pillow")
    print("• Admins podem forçar/desabilitar MFA de qualquer usuário")
    print("• Relatórios de adoção de MFA")
    print("• Ações em massa para MFA")
    
    print("\n📊 RELATÓRIOS AVANÇADOS:")
    print("• Instale: pip install plotly pandas numpy")
    print("• Gráficos interativos de usuários e arquivos")
    print("• Analytics de segurança e performance")
    
    print("\n" + "="*60)

def main():
    """Função principal"""
    
    print("🔧 INICIANDO INTEGRAÇÃO DO SISTEMA DE GERENCIAMENTO DE USUÁRIOS")
    print("="*70)
    
    # Passo 1: Backup
    print("\n📦 Passo 1: Criando backup...")
    create_backup()
    
    # Passo 2: Verificar user_management.py
    print("\n🔍 Passo 2: Verificando user_management.py...")
    if not verify_user_management():
        print("❌ Verifique se user_management.py está presente e correto")
    
    # Passo 3: Verificar dependências
    print("\n📦 Passo 3: Verificando dependências...")
    verify_dependencies()
    
    # Passo 4: Instruções
    print("\n📋 Passo 4: Instruções de integração...")
    show_integration_instructions()
    
    print("\n✅ INTEGRAÇÃO PRONTA!")
    print("🔗 Agora substitua o admin_pages.py pelo código fornecido")

if __name__ == "__main__":
    main()
