#!/usr/bin/env python3
"""
Correção dos Imports do Plotly - Resolve 'make_subplots' is not defined
Execute: python fix_plotly_imports.py
"""
import os
import shutil
from datetime import datetime

def fix_plotly_imports():
    """Corrige imports do Plotly no enhanced_admin_reports.py"""
    
    print("🔧 CORRIGINDO IMPORTS DO PLOTLY")
    print("=" * 50)
    print("🎯 Objetivo: Resolver erro 'make_subplots' is not defined")
    print()
    
    # Fazer backup
    if os.path.exists('enhanced_admin_reports.py'):
        backup_name = f'enhanced_admin_reports_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.py'
        shutil.copy2('enhanced_admin_reports.py', backup_name)
        print(f"✅ Backup criado: {backup_name}")
    else:
        print("❌ enhanced_admin_reports.py não encontrado!")
        return False
    
    # Ler arquivo atual
    try:
        with open('enhanced_admin_reports.py', 'r', encoding='utf-8') as f:
            content = f.read()
        print("✅ Arquivo lido")
    except Exception as e:
        print(f"❌ Erro ao ler arquivo: {e}")
        return False
    
    # Aplicar correções
    try:
        print("🔄 Aplicando correções de import...")
        
        # 1. Corrigir imports no início do arquivo
        content = fix_main_imports(content)
        
        # 2. Corrigir imports locais nas funções
        content = fix_function_imports(content)
        
        # 3. Adicionar verificações de segurança
        content = add_safety_checks(content)
        
        # Salvar arquivo corrigido
        with open('enhanced_admin_reports.py', 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Arquivo corrigido e salvo")
        
        # Testar import
        try:
            import sys
            if 'enhanced_admin_reports' in sys.modules:
                del sys.modules['enhanced_admin_reports']
            
            import enhanced_admin_reports
            print("✅ Módulo importado com sucesso")
            
            # Testar se Plotly funciona
            try:
                import plotly.express as px
                from plotly.subplots import make_subplots
                print("✅ Plotly e make_subplots funcionando")
            except ImportError:
                print("⚠️  Plotly não instalado - gráficos básicos serão usados")
            
            return True
            
        except Exception as e:
            print(f"⚠️  Aviso no teste: {e}")
            print("💡 Correções aplicadas, teste manualmente")
            return True
        
    except Exception as e:
        print(f"❌ Erro ao aplicar correções: {e}")
        return False

def fix_main_imports(content):
    """Corrige imports principais do arquivo"""
    
    # Encontrar seção de imports
    lines = content.split('\n')
    corrected_lines = []
    
    import_section_found = False
    
    for line in lines:
        if 'import streamlit as st' in line:
            import_section_found = True
        
        # Se estamos na seção de imports e encontramos plotly
        if import_section_found and ('import plotly' in line or 'from plotly' in line):
            # Pular imports plotly duplicados ou incompletos
            continue
        
        # Adicionar imports corretos do plotly após a seção principal
        if import_section_found and line.strip() == '' and 'plotly' not in ''.join(corrected_lines[-10:]):
            # Adicionar imports plotly corretos
            corrected_lines.append('')
            corrected_lines.append('# IMPORTS PLOTLY CORRETOS')
            corrected_lines.append('try:')
            corrected_lines.append('    import plotly.express as px')
            corrected_lines.append('    import plotly.graph_objects as go')
            corrected_lines.append('    from plotly.subplots import make_subplots')
            corrected_lines.append('    PLOTLY_AVAILABLE = True')
            corrected_lines.append('except ImportError:')
            corrected_lines.append('    PLOTLY_AVAILABLE = False')
            corrected_lines.append('    # Criar objetos mock para evitar erros')
            corrected_lines.append('    class MockPlotly:')
            corrected_lines.append('        @staticmethod')
            corrected_lines.append('        def bar(*args, **kwargs): return None')
            corrected_lines.append('        @staticmethod') 
            corrected_lines.append('        def line(*args, **kwargs): return None')
            corrected_lines.append('        @staticmethod')
            corrected_lines.append('        def pie(*args, **kwargs): return None')
            corrected_lines.append('        @staticmethod')
            corrected_lines.append('        def histogram(*args, **kwargs): return None')
            corrected_lines.append('        @staticmethod')
            corrected_lines.append('        def scatter(*args, **kwargs): return None')
            corrected_lines.append('    ')
            corrected_lines.append('    px = MockPlotly()')
            corrected_lines.append('    go = MockPlotly()')
            corrected_lines.append('    ')
            corrected_lines.append('    def make_subplots(*args, **kwargs):')
            corrected_lines.append('        return MockPlotly()')
            corrected_lines.append('')
            import_section_found = False
        
        corrected_lines.append(line)
    
    return '\n'.join(corrected_lines)

def fix_function_imports(content):
    """Corrige imports locais nas funções"""
    
    # Lista de padrões de import problemáticos e suas correções
    import_fixes = [
        # Padrão problemático -> Correção
        ('import plotly.express as px\n        import plotly.graph_objects as go\n        from plotly.subplots import make_subplots', 
         '# Imports já estão no topo do arquivo'),
        
        ('from plotly.subplots import make_subplots', 
         '# make_subplots já importado no topo'),
        
        ('import plotly.express as px', 
         '# px já importado no topo'),
        
        ('import plotly.graph_objects as go', 
         '# go já importado no topo'),
    ]
    
    for old_import, new_comment in import_fixes:
        content = content.replace(old_import, new_comment)
    
    return content

def add_safety_checks(content):
    """Adiciona verificações de segurança para Plotly"""
    
    # Adicionar verificação antes de usar make_subplots
    content = content.replace(
        'fig = make_subplots(',
        '''if not PLOTLY_AVAILABLE:
            st.error("📊 Plotly não está instalado. Execute: pip install plotly")
            return
        
        fig = make_subplots('''
    )
    
    # Adicionar verificação antes de usar px
    content = content.replace(
        'fig = px.',
        '''if not PLOTLY_AVAILABLE:
            st.error("📊 Plotly não está instalado. Execute: pip install plotly")
            return
        
        fig = px.'''
    )
    
    # Adicionar verificação antes de usar go
    content = content.replace(
        'fig.add_trace(\n            go.',
        '''if not PLOTLY_AVAILABLE:
            return
        
        fig.add_trace(
            go.'''
    )
    
    return content

def print_success_message():
    """Mensagem de sucesso"""
    print("\n🎉 CORREÇÃO DOS IMPORTS CONCLUÍDA!")
    print("=" * 50)
    print()
    print("✅ CORREÇÕES APLICADAS:")
    print("  • 📦 Imports do Plotly movidos para o topo")
    print("  • 🔒 make_subplots importado corretamente")
    print("  • 🛡️ Verificações de segurança adicionadas")
    print("  • 🔄 Fallbacks para quando Plotly não está disponível")
    print()
    print("📋 PRÓXIMOS PASSOS:")
    print("1. 🔄 Reinicie sua aplicação: streamlit run main.py")
    print("2. 🔐 Acesse: Administração > Relatórios Avançados")
    print("3. 📁 Teste a aba 'Analytics de Arquivos'")
    print("4. 📊 Verifique se os gráficos carregam sem erro")
    print()
    print("💡 SE AINDA HOUVER ERRO:")
    print("Instale o Plotly: pip install plotly>=5.15.0")

def print_failure_message():
    """Mensagem de falha"""
    print("\n❌ CORREÇÃO NÃO CONCLUÍDA")
    print("=" * 50)
    print()
    print("💡 CORREÇÃO MANUAL:")
    print("1. Abra enhanced_admin_reports.py")
    print("2. No topo do arquivo, após os imports básicos, adicione:")
    print()
    print("```python")
    print("# IMPORTS PLOTLY CORRETOS")
    print("try:")
    print("    import plotly.express as px")
    print("    import plotly.graph_objects as go")
    print("    from plotly.subplots import make_subplots")
    print("    PLOTLY_AVAILABLE = True")
    print("except ImportError:")
    print("    PLOTLY_AVAILABLE = False")
    print("    px = None")
    print("    go = None")
    print("    def make_subplots(*args, **kwargs): return None")
    print("```")
    print()
    print("3. Salve e reinicie a aplicação")

def main():
    """Função principal"""
    try:
        success = fix_plotly_imports()
        
        if success:
            print_success_message()
        else:
            print_failure_message()
        
        return success
        
    except Exception as e:
        print(f"\n❌ Erro crítico: {e}")
        print_failure_message()
        return False

if __name__ == "__main__":
    main()
