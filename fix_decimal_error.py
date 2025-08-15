#!/usr/bin/env python3
"""
Script para corrigir erro de Decimal/Float nos relatórios
Execute: python fix_decimal_error.py
"""
import os
import shutil
from datetime import datetime

def fix_decimal_error():
    """Corrige o erro de divisão Decimal/Float"""
    
    print("🔧 CORRIGINDO ERRO DECIMAL/FLOAT NOS RELATÓRIOS")
    print("=" * 60)
    
    # 1. Fazer backup
    if os.path.exists('admin_reports_data.py'):
        backup_name = f'admin_reports_data_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.py'
        shutil.copy2('admin_reports_data.py', backup_name)
        print(f"✅ Backup criado: {backup_name}")
    
    # 2. Ler arquivo atual
    try:
        with open('admin_reports_data.py', 'r', encoding='utf-8') as f:
            content = f.read()
        print("✅ Arquivo lido com sucesso")
    except FileNotFoundError:
        print("❌ Arquivo admin_reports_data.py não encontrado")
        return False
    
    # 3. Aplicar correções específicas
    corrections_made = 0
    
    # Correção 1: Adicionar import decimal
    if 'from decimal import Decimal' not in content:
        content = content.replace(
            'import logging',
            'import logging\nfrom decimal import Decimal'
        )
        corrections_made += 1
        print("✅ Import de Decimal adicionado")
    
    # Correção 2: Adicionar funções auxiliares se não existirem
    if '_safe_float_division' not in content:
        helper_functions = '''
def _safe_float_division(numerator, denominator):
    """Função auxiliar para divisão segura entre Decimal e float"""
    try:
        # Converter ambos para float se necessário
        if isinstance(numerator, Decimal):
            numerator = float(numerator)
        if isinstance(denominator, Decimal):
            denominator = float(denominator)
        
        if denominator == 0:
            return 0.0
        
        return float(numerator) / float(denominator)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0

def _safe_numeric_conversion(value):
    """Converte valor numérico de forma segura para float"""
    try:
        if value is None:
            return 0.0
        if isinstance(value, Decimal):
            return float(value)
        return float(value)
    except (TypeError, ValueError):
        return 0.0

'''
        
        # Inserir após os imports
        import_end = content.find('\nlogger = logging.getLogger(__name__)')
        if import_end != -1:
            content = content[:import_end] + helper_functions + content[import_end:]
            corrections_made += 1
            print("✅ Funções auxiliares adicionadas")
    
    # Correção 3: Corrigir divisões problemáticas
    problematic_patterns = [
        # Padrão 1: file_size / (1024.0 * 1024.0)
        (r'file_size / \(1024\.0 \* 1024\.0\)', 
         'CAST(file_size AS FLOAT) / (1024.0 * 1024.0)'),
        
        # Padrão 2: SUM(file_size) / (1024.0 * 1024.0 * 1024.0)
        (r'SUM\(file_size\) / \(1024\.0 \* 1024\.0 \* 1024\.0\)', 
         'CAST(SUM(file_size) AS FLOAT) / (1024.0 * 1024.0 * 1024.0)'),
        
        # Padrão 3: Adicionar CAST em queries SQL
        (r'SUM\(f\.file_size\) / \(1024\.0 \* 1024\.0 \* 1024\.0\)', 
         'CAST(SUM(f.file_size) AS FLOAT) / (1024.0 * 1024.0 * 1024.0)'),
    ]
    
    import re
    
    for pattern, replacement in problematic_patterns:
        old_content = content
        content = re.sub(pattern, replacement, content)
        if content != old_content:
            corrections_made += 1
            print(f"✅ Padrão corrigido: {pattern[:50]}...")
    
    # Correção 4: Envolver operações de divisão com funções seguras
    division_fixes = [
        # Performance metrics
        ('avg_size_mb / upload_speed', '_safe_float_division(avg_size_mb, upload_speed)'),
        ('size_mb / random.uniform(10, 20)', '_safe_float_division(size_mb, random.uniform(10, 20))'),
        ('(size_mb / random.uniform(10, 20))', '_safe_float_division(size_mb, random.uniform(10, 20))'),
        
        # Percentual calculations
        ('* 100.0 / COUNT(*)', '* 100.0 / NULLIF(COUNT(*), 0)'),
    ]
    
    for old_text, new_text in division_fixes:
        if old_text in content:
            content = content.replace(old_text, new_text)
            corrections_made += 1
            print(f"✅ Divisão corrigida: {old_text}")
    
    # Correção 5: Substituir processamento de resultados
    if 'for row in cursor.fetchall():' in content and '_safe_numeric_conversion' not in content:
        # Esta será uma correção mais complexa que precisa ser feita manualmente
        print("⚠️  Alguns resultados podem precisar de _safe_numeric_conversion")
    
    # 4. Escrever arquivo corrigido
    try:
        with open('admin_reports_data.py', 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Arquivo corrigido com {corrections_made} alterações")
        
        # 5. Teste básico
        try:
            import admin_reports_data
            print("✅ Módulo importado com sucesso após correções")
            return True
        except Exception as e:
            print(f"❌ Erro ao importar módulo corrigido: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Erro ao salvar arquivo: {e}")
        return False

def main():
    """Função principal"""
    success = fix_decimal_error()
    
    if success:
        print("\n" + "🎉 CORREÇÃO CONCLUÍDA COM SUCESSO!")
        print("=" * 60)
        print("📋 Próximos passos:")
        print("1. Reinicie sua aplicação Streamlit")
        print("2. Teste os relatórios avançados")
        print("3. Verifique se não há mais erros de Decimal")
        print("\n💡 Se ainda houver erros, use o arquivo completo corrigido")
    else:
        print("\n" + "❌ CORREÇÃO NÃO CONCLUÍDA")
        print("=" * 60)
        print("💡 Recomendações:")
        print("1. Substitua manualmente o admin_reports_data.py")
        print("2. Use o arquivo completo corrigido fornecido")
        print("3. Verifique se todas as dependências estão instaladas")

if __name__ == "__main__":
    main()
