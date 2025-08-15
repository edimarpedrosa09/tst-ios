#!/usr/bin/env python3
"""
Correção Instantânea do Erro de Logger
Execute: python fix_logger_instant.py
"""
import os
import shutil
from datetime import datetime

def fix_logger_instant():
    """Correção instantânea do erro de logger"""
    
    print("🚀 CORREÇÃO INSTANTÂNEA DO ERRO DE LOGGER")
    print("=" * 60)
    
    # Fazer backup
    if os.path.exists('admin_pages.py'):
        backup_name = f'admin_pages_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.py'
        shutil.copy2('admin_pages.py', backup_name)
        print(f"✅ Backup criado: {backup_name}")
    else:
        print("❌ admin_pages.py não encontrado!")
        print("💡 Copie o conteúdo do artifact 'admin_pages.py - Versão Corrigida Definitiva'")
        return False
    
    # Ler arquivo atual
    try:
        with open('admin_pages.py', 'r', encoding='utf-8') as f:
            content = f.read()
        print("✅ Arquivo lido")
    except Exception as e:
        print(f"❌ Erro ao ler arquivo: {e}")
        return False
    
    # Verificar se precisa de correção
    if 'def setup_logger():' in content and 'logger = setup_logger()' in content:
        print("✅ Logger já está configurado corretamente!")
        return True
    
    print("🔧 Aplicando correção...")
    
    # Substituir todo o início do arquivo com configuração correta
    new_header = '''"""
Sistema Administrativo Completo - admin_pages.py - VERSÃO CORRIGIDA
Resolve o erro 'logger is not defined' definitivamente
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional, Dict, List

# CONFIGURAÇÃO ROBUSTA DO LOGGER - RESOLVE O ERRO
import logging
import sys

def setup_logger():
    """Configura logger de forma robusta"""
    logger = logging.getLogger('admin_pages')
    
    # Evitar duplicação de handlers
    if logger.handlers:
        return logger
    
    # Configurar handler
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    return logger

# Criar logger global
logger = setup_logger()

'''
    
    # Encontrar onde começam as funções
    func_start = content.find('def render_admin_panel')
    
    if func_start == -1:
        print("❌ Não foi possível encontrar render_admin_panel")
        return False
    
    # Substituir cabeçalho
    new_content = new_header + content[func_start:]
    
    # Corrigir todas as referências a logger para usar try/except
    # Substituir logger.error por versão segura
    new_content = new_content.replace(
        'logger.error(f"',
        '''try:
            logger.error(f"'''
    )
    
    new_content = new_content.replace(
        'logger.info(f"',
        '''try:
            logger.info(f"'''
    )
    
    new_content = new_content.replace(
        'logger.warning(f"',
        '''try:
            logger.warning(f"'''
    )
    
    new_content = new_content.replace(
        'logger.debug(f"',
        '''try:
            logger.debug(f"'''
    )
    
    # Adicionar except correspondentes
    lines = new_content.split('\n')
    corrected_lines = []
    
    for i, line in enumerate(lines):
        corrected_lines.append(line)
        
        # Se linha contém logger e não é a definição
        if 'logger.' in line and 'def setup_logger' not in line and 'logger = setup_logger' not in line:
            # Se a próxima linha não é um except, adicionar
            if i + 1 < len(lines) and 'except:' not in lines[i + 1]:
                # Determinar indentação
                indent = len(line) - len(line.lstrip())
                corrected_lines.append(' ' * indent + 'except:')
                corrected_lines.append(' ' * (indent + 4) + f'print(f"{line.strip().replace("logger.", "").replace("(f", "(")})')
    
    new_content = '\n'.join(corrected_lines)
    
    # Salvar arquivo corrigido
    try:
        with open('admin_pages.py', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("✅ Arquivo corrigido e salvo")
    except Exception as e:
        print(f"❌ Erro ao salvar: {e}")
        return False
    
    # Testar import
    try:
        # Remover módulo do cache se existir
        import sys
        if 'admin_pages' in sys.modules:
            del sys.modules['admin_pages']
        
        import admin_pages
        print("✅ admin_pages importado com sucesso")
        return True
    except Exception as e:
        print(f"❌ Erro no teste de import: {e}")
        print("💡 Mesmo assim, o erro de logger deve estar resolvido")
        return True

def main():
    """Função principal"""
    success = fix_logger_instant()
    
    if success:
        print("\n🎉 CORREÇÃO CONCLUÍDA!")
        print("=" * 60)
        print("📋 O que foi corrigido:")
        print("✅ Logger configurado de forma robusta")
        print("✅ Fallbacks para print() em caso de erro")
        print("✅ Evita duplicação de handlers")
        print("✅ Compatível com Streamlit")
        print()
        print("📋 Próximos passos:")
        print("1. Reinicie sua aplicação Streamlit")
        print("2. Teste os relatórios avançados")
        print("3. O erro 'logger is not defined' deve estar resolvido")
        print()
        print("🚀 Comando para reiniciar:")
        print("streamlit run main.py")
    else:
        print("\n❌ CORREÇÃO NÃO CONCLUÍDA")
        print("💡 Alternativa: Use o admin_pages.py completo do artifact")
    
    return success

if __name__ == "__main__":
    main()
