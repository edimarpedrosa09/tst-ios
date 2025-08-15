#!/usr/bin/env python3
"""
Script de Correção Rápida do Sistema Admin
Execute: python fix_admin_quick.py
"""
import os
import shutil
from datetime import datetime

def fix_admin_system():
    """Corrige rapidamente o sistema administrativo"""
    
    print("🔧 CORREÇÃO RÁPIDA DO SISTEMA ADMINISTRATIVO")
    print("=" * 60)
    
    # 1. Verificar se admin_pages.py existe
    if not os.path.exists('admin_pages.py'):
        print("❌ admin_pages.py não encontrado!")
        print("📝 Criando admin_pages.py...")
        
        # O conteúdo já está no artifact acima
        # Você pode copiar e colar o conteúdo do artifact
        print("✅ Copie o conteúdo do admin_pages.py do artifact acima")
        print("💡 Ou baixe o arquivo do artifact e salve como admin_pages.py")
        return False
    
    print("✅ admin_pages.py encontrado")
    
    # 2. Verificar imports necessários
    try:
        with open('admin_pages.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verificações básicas
        checks = [
            ('render_admin_panel', 'Função principal do admin'),
            ('is_admin_user', 'Verificação de permissões'),
            ('render_advanced_reports_section', 'Relatórios avançados'),
            ('render_admin_dashboard', 'Dashboard administrativo')
        ]
        
        missing = []
        for func, desc in checks:
            if func in content:
                print(f"✅ {desc}")
            else:
                missing.append((func, desc))
                print(f"❌ {desc}")
        
        if missing:
            print(f"\n⚠️  {len(missing)} componentes faltando")
            print("💡 Use o admin_pages.py completo do artifact")
            return False
        
    except Exception as e:
        print(f"❌ Erro ao verificar admin_pages.py: {e}")
        return False
    
    # 3. Testar importação
    try:
        import admin_pages
        print("✅ admin_pages importado com sucesso")
    except ImportError as e:
        print(f"❌ Erro de importação: {e}")
        return False
    
    # 4. Verificar se main.py chama corretamente
    try:
        with open('main.py', 'r', encoding='utf-8') as f:
            main_content = f.read()
        
        if 'from admin_pages import render_admin_panel' in main_content:
            print("✅ main.py importa admin_pages corretamente")
        else:
            print("⚠️  main.py pode não estar importando admin_pages")
            print("💡 Verifique se tem: from admin_pages import render_admin_panel")
    
    except Exception as e:
        print(f"⚠️  Não foi possível verificar main.py: {e}")
    
    # 5. Verificar permissões de admin
    print("\n🔍 VERIFICAÇÃO DE PERMISSÕES ADMIN:")
    print("Para ter acesso admin, seu username deve:")
    print("1. Conter a palavra 'admin' (ex: admin, admin123, administrator)")
    print("2. Ou ser um dos usernames padrão: root, adm, administrador, sa")
    print("3. Ou ser o primeiro usuário criado no sistema")
    print()
    print("💡 DICA PARA TESTES:")
    print("Se quiser permitir qualquer usuário como admin temporariamente,")
    print("descomente a linha 'return True' na função is_admin_user()")
    
    print("\n✅ VERIFICAÇÃO CONCLUÍDA!")
    print("\n📋 PRÓXIMOS PASSOS:")
    print("1. Certifique-se que admin_pages.py está presente")
    print("2. Reinicie sua aplicação Streamlit")
    print("3. Faça login com username que contenha 'admin'")
    print("4. Acesse a aba 'Administração'")
    print("5. Teste os relatórios avançados")
    
    return True

def create_test_admin_user():
    """Cria usuário admin de teste"""
    print("\n👤 CRIANDO USUÁRIO ADMIN DE TESTE")
    print("-" * 40)
    
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        
        # Criar usuário admin de teste
        admin_created = db_manager.create_user_safe(
            username="admin",
            password="admin123",
            email="admin@teste.com",
            full_name="Administrador Teste",
            role="admin"
        )
        
        if admin_created:
            print("✅ Usuário admin criado!")
            print("👤 Username: admin")
            print("🔑 Senha: admin123")
            print("📧 Email: admin@teste.com")
            print()
            print("⚠️  IMPORTANTE: Altere a senha após o primeiro login!")
        else:
            print("⚠️  Usuário 'admin' já existe ou erro na criação")
            
    except Exception as e:
        print(f"❌ Erro ao criar usuário admin: {e}")
        print("💡 Crie manualmente um usuário com username que contenha 'admin'")

def main():
    """Função principal"""
    try:
        if fix_admin_system():
            
            # Perguntar se quer criar usuário admin
            print("\n" + "="*60)
            response = input("🤔 Deseja criar um usuário admin de teste? (s/n): ").lower().strip()
            
            if response in ['s', 'sim', 'y', 'yes']:
                create_test_admin_user()
            
            print("\n🎉 CORREÇÃO CONCLUÍDA!")
            return True
        else:
            print("\n❌ CORREÇÃO NÃO CONCLUÍDA")
            return False
            
    except Exception as e:
        print(f"\n❌ Erro na correção: {e}")
        return False

if __name__ == "__main__":
    main()
