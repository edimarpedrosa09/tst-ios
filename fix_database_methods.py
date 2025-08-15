#!/usr/bin/env python3
"""
Script para Corrigir DatabaseManager - Adiciona Métodos Faltantes
Execute: python fix_database_methods.py
"""
import os
import shutil
from datetime import datetime

def create_backup():
    """Criar backup dos arquivos atuais"""
    backup_dir = f"backup_database_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    files_to_backup = ['database.py', 'admin_pages.py', 'main.py']
    
    created_backup = False
    for file in files_to_backup:
        if os.path.exists(file):
            if not created_backup:
                os.makedirs(backup_dir, exist_ok=True)
                created_backup = True
            
            shutil.copy2(file, os.path.join(backup_dir, f"{file}.backup"))
            print(f"✅ Backup criado: {file}")
    
    if created_backup:
        print(f"📁 Backup salvo em: {backup_dir}")
        return True
    else:
        print("⚠️ Nenhum arquivo encontrado para backup")
        return False

def analyze_current_database():
    """Analisa o database.py atual"""
    if not os.path.exists('database.py'):
        print("❌ database.py não encontrado!")
        return False
    
    with open('database.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Métodos necessários
    required_methods = [
        'get_user_files',
        'save_file_metadata', 
        'delete_file_metadata',
        'record_download',
        'create_session_token',
        'validate_session_token',
        'invalidate_session_token',
        'cleanup_expired_sessions',
        'create_temporary_link',
        'validate_temporary_link',
        'get_user_temporary_links',
        'deactivate_temporary_link',
        'authenticate_user',
        'create_user',
        'get_system_stats',
        'user_exists',
        'get_user_info',
        'update_user_info'
    ]
    
    missing_methods = []
    for method in required_methods:
        if f"def {method}" not in content:
            missing_methods.append(method)
    
    print(f"🔍 Análise do database.py:")
    print(f"📊 Métodos necessários: {len(required_methods)}")
    print(f"❌ Métodos faltando: {len(missing_methods)}")
    
    if missing_methods:
        print(f"\n📋 Métodos faltantes:")
        for method in missing_methods:
            print(f"  • {method}")
        return False
    else:
        print("✅ Todos os métodos estão presentes!")
        return True

def show_error_analysis():
    """Mostra análise dos erros encontrados"""
    print("\n" + "="*60)
    print("🔍 ANÁLISE DOS ERROS ENCONTRADOS")
    print("="*60)
    
    print("\n❌ ERRO PRINCIPAL:")
    print("'DatabaseManager' object has no attribute 'get_user_files'")
    
    print("\n🔍 PROBLEMAS IDENTIFICADOS:")
    print("1. ❌ Método get_user_files() faltando no DatabaseManager")
    print("2. ❌ Outros métodos de arquivo podem estar faltando")
    print("3. ❌ Métodos de sessão podem estar incompletos")
    print("4. ❌ Métodos de links temporários podem estar faltando")
    print("5. ❌ Botões em formulários causando erros no Streamlit")
    
    print("\n✅ SOLUÇÕES IMPLEMENTADAS:")
    print("1. ✅ DatabaseManager COMPLETO com TODOS os métodos")
    print("2. ✅ Métodos de arquivo: save, get, delete, download")
    print("3. ✅ Métodos de sessão: create, validate, invalidate")
    print("4. ✅ Métodos de links temporários: create, validate, list")
    print("5. ✅ Métodos de usuário: authenticate, create, info")
    print("6. ✅ Métodos de sistema: stats, exists, update")
    print("7. ✅ Admin pages SEM formulários aninhados")
    
    print("\n🎯 COMPONENTES CORRIGIDOS:")
    print("• database.py - Versão completa com TODOS os métodos")
    print("• admin_pages.py - Versão sem formulários aninhados")
    print("• Tabelas SQL com índices e views otimizadas")
    print("• Sistema de logs administrativos")
    print("• Função SQL para conversão bytes->GB")

def show_integration_steps():
    """Mostra passos de integração"""
    print("\n" + "="*60)
    print("🚀 PASSOS PARA CORRIGIR O SISTEMA")
    print("="*60)
    
    print("\n📋 PASSO 1: Substituir Arquivos")
    print("1. Substitua database.py pelo código corrigido")
    print("2. Substitua admin_pages.py pelo código sem formulários")
    print("3. Mantenha backup dos arquivos originais")
    
    print("\n📋 PASSO 2: Reinicializar Banco")
    print("1. Execute a aplicação uma vez para criar as novas tabelas")
    print("2. O sistema criará automaticamente:")
    print("   • Tabelas faltantes (users_extended, admin_logs)")
    print("   • Função SQL bytes_to_gb()")
    print("   • View system_stats_gb")
    print("   • Índices para performance")
    
    print("\n📋 PASSO 3: Testar Sistema")
    print("1. Reinicie aplicação Streamlit")
    print("2. Faça login como admin")
    print("3. Teste upload de arquivos")
    print("4. Teste listagem de arquivos")
    print("5. Teste painel administrativo")
    
    print("\n📋 PASSO 4: Verificar Logs")
    print("1. Monitore logs para erros")
    print("2. Verifique se métodos funcionam")
    print("3. Teste todas as funcionalidades")

def show_method_overview():
    """Mostra visão geral dos métodos adicionados"""
    print("\n" + "="*60)
    print("📚 MÉTODOS ADICIONADOS NO DATABASEMANAGER")
    print("="*60)
    
    print("\n🔐 AUTENTICAÇÃO:")
    print("• authenticate_user() - Autentica usuário")
    print("• create_user() - Cria novo usuário")
    print("• user_exists() - Verifica se usuário existe")
    print("• get_user_info() - Obtém info do usuário")
    print("• update_user_info() - Atualiza info do usuário")
    
    print("\n📁 GERENCIAMENTO DE ARQUIVOS:")
    print("• save_file_metadata() - Salva metadados do arquivo")
    print("• get_user_files() - Lista arquivos do usuário") 
    print("• get_all_files() - Lista todos os arquivos (admin)")
    print("• delete_file_metadata() - Remove metadados")
    print("• record_download() - Registra download")
    print("• get_file_info() - Info específica do arquivo")
    
    print("\n🔗 LINKS TEMPORÁRIOS:")
    print("• create_temporary_link() - Cria link temporário")
    print("• validate_temporary_link() - Valida acesso")
    print("• get_user_temporary_links() - Lista links do usuário")
    print("• deactivate_temporary_link() - Desativa link")
    
    print("\n🔒 SESSÕES:")
    print("• create_session_token() - Cria token de sessão")
    print("• validate_session_token() - Valida token")
    print("• invalidate_session_token() - Invalida token") 
    print("• cleanup_expired_sessions() - Remove tokens expirados")
    
    print("\n📊 SISTEMA:")
    print("• get_system_stats() - Estatísticas gerais")
    print("• init_database() - Inicializa todas as tabelas")

def main():
    """Função principal"""
    print("🔧 CORREÇÃO DO DATABASEMANAGER - MÉTODOS FALTANTES")
    print("="*70)
    
    # Criar backup
    print("\n📦 Criando backup...")
    create_backup()
    
    # Analisar situação atual
    print("\n🔍 Analisando database.py atual...")
    database_ok = analyze_current_database()
    
    # Mostrar análise de erros
    show_error_analysis()
    
    # Mostrar métodos adicionados
    show_method_overview()
    
    # Mostrar passos de integração
    show_integration_steps()
    
    print("\n" + "="*70)
    print("✅ ANÁLISE CONCLUÍDA!")
    
    if not database_ok:
        print("🚨 AÇÃO NECESSÁRIA: Substitua database.py pelo código corrigido")
        print("🚨 AÇÃO NECESSÁRIA: Substitua admin_pages.py pelo código sem formulários")
    else:
        print("✅ DatabaseManager parece estar completo")
    
    print("\n💡 DICA: Use os códigos fornecidos nos artifacts para corrigir os problemas")
    print("="*70)

if __name__ == "__main__":
    main()
