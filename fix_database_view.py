#!/usr/bin/env python3
"""
Script para Corrigir View SQL Conflitante
Execute: python fix_database_view.py
"""
import psycopg2
import os
from datetime import datetime

def get_database_url():
    """Obtém URL do banco de dados"""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("❌ DATABASE_URL não encontrada nas variáveis de ambiente")
        return None
    return database_url

def fix_database_views():
    """Corrige views problemáticas no banco"""
    database_url = get_database_url()
    if not database_url:
        return False
    
    try:
        print("🔧 Conectando ao banco de dados...")
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        print("🗑️ Removendo views conflitantes...")
        
        # Remover views que podem causar conflito
        views_to_drop = [
            'system_stats_gb',
            'system_statistics', 
            'admin_stats',
            'file_stats'
        ]
        
        for view in views_to_drop:
            try:
                cursor.execute(f"DROP VIEW IF EXISTS {view} CASCADE")
                print(f"✅ View removida: {view}")
            except Exception as e:
                print(f"⚠️ Erro ao remover {view}: {e}")
        
        print("🔧 Criando função bytes_to_gb...")
        
        # Recriar função de conversão
        cursor.execute("""
            CREATE OR REPLACE FUNCTION bytes_to_gb(bytes_value BIGINT)
            RETURNS NUMERIC(10,6) AS $$
            BEGIN
                IF bytes_value IS NULL OR bytes_value = 0 THEN
                    RETURN 0;
                END IF;
                RETURN ROUND((bytes_value::NUMERIC / (1024.0 * 1024.0 * 1024.0)), 6);
            END;
            $$ LANGUAGE plpgsql;
        """)
        print("✅ Função bytes_to_gb criada")
        
        print("📊 Criando view system_stats_gb corrigida...")
        
        # Criar view corrigida
        cursor.execute("""
            CREATE VIEW system_stats_gb AS
            SELECT 
                (SELECT COUNT(*) FROM users WHERE is_active = TRUE) as total_users,
                (SELECT COUNT(*) FROM files) as total_files,
                bytes_to_gb(COALESCE((SELECT SUM(file_size) FROM files), 0)) as total_storage_gb,
                bytes_to_gb(COALESCE((SELECT SUM(file_size) FROM files WHERE uploaded_at >= NOW() - INTERVAL '30 days'), 0)) as storage_growth_30d_gb,
                (SELECT COUNT(*) FROM files WHERE uploaded_at >= NOW() - INTERVAL '30 days') as new_files_30d,
                (SELECT COUNT(*) FROM users WHERE mfa_enabled = TRUE AND is_active = TRUE) as mfa_users,
                CASE 
                    WHEN (SELECT COUNT(*) FROM users WHERE is_active = TRUE) > 0 
                    THEN ROUND(100.0, 2)
                    ELSE 0 
                END as activity_rate
        """)
        print("✅ View system_stats_gb criada")
        
        # Verificar se tabelas necessárias existem
        print("🔍 Verificando tabelas necessárias...")
        
        required_tables = [
            'users', 'files', 'downloads', 'user_sessions', 
            'temporary_links', 'users_extended', 'admin_logs'
        ]
        
        for table in required_tables:
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = %s
                )
            """, (table,))
            
            exists = cursor.fetchone()[0]
            status = "✅" if exists else "❌"
            print(f"  {status} Tabela: {table}")
        
        # Commit das mudanças
        conn.commit()
        print("💾 Mudanças salvas no banco")
        
        cursor.close()
        conn.close()
        
        print("✅ Correção do banco concluída com sucesso!")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao corrigir banco: {e}")
        return False

def test_database_connection():
    """Testa conexão com o banco"""
    database_url = get_database_url()
    if not database_url:
        return False
    
    try:
        print("🔍 Testando conexão com banco...")
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Teste simples
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        print(f"✅ Conexão OK - PostgreSQL: {version}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Erro de conexão: {e}")
        return False

def create_minimal_database():
    """Cria estrutura mínima do banco"""
    database_url = get_database_url()
    if not database_url:
        return False
    
    try:
        print("🏗️ Criando estrutura mínima do banco...")
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()
        
        # Tabela de usuários básica
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100),
                is_active BOOLEAN DEFAULT TRUE,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("✅ Tabela users criada")
        
        # Tabela de arquivos básica
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                file_key VARCHAR(255) UNIQUE NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                file_size BIGINT,
                mime_type VARCHAR(100),
                uploaded_by VARCHAR(50),
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("✅ Tabela files criada")
        
        # Tabela de downloads básica
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id SERIAL PRIMARY KEY,
                file_key VARCHAR(255),
                downloaded_by VARCHAR(50),
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45)
            )
        """)
        print("✅ Tabela downloads criada")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("✅ Estrutura mínima criada!")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao criar estrutura: {e}")
        return False

def main():
    """Função principal"""
    print("🔧 CORREÇÃO DE VIEWS SQL CONFLITANTES")
    print("="*50)
    
    # Testar conexão
    if not test_database_connection():
        print("❌ Não foi possível conectar ao banco")
        print("💡 Verifique se DATABASE_URL está configurada")
        return
    
    # Corrigir views
    print("\n🔧 Corrigindo views problemáticas...")
    if fix_database_views():
        print("✅ Views corrigidas!")
    else:
        print("❌ Erro ao corrigir views")
        
        # Tentar criar estrutura mínima
        print("\n🏗️ Tentando criar estrutura mínima...")
        if create_minimal_database():
            print("✅ Estrutura mínima criada!")
        else:
            print("❌ Falha na criação da estrutura mínima")
    
    print("\n" + "="*50)
    print("🚀 PRÓXIMOS PASSOS:")
    print("1. Reinicie a aplicação Streamlit")
    print("2. Teste o login")
    print("3. Verifique se os erros de view sumiram")
    print("4. Se ainda houver problemas, execute novamente este script")
    print("="*50)

if __name__ == "__main__":
    main()
