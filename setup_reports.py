#!/usr/bin/env python3
"""
Script Completo para Configurar Relatórios Avançados
Execute: python setup_reports.py
"""
import os
import sys
import shutil
import subprocess
import logging
from datetime import datetime

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReportsSetup:
    """Classe para configuração dos relatórios avançados"""
    
    def __init__(self):
        self.required_files = [
            'enhanced_admin_reports.py',
            'admin_reports_data.py', 
            'reports_config.py',
            'admin_pages.py',
            'main.py'
        ]
        
        self.required_packages = [
            'plotly>=5.15.0',
            'pandas>=1.5.0',
            'numpy>=1.24.0',
            'matplotlib>=3.6.0',
            'seaborn>=0.12.0'
        ]
        
        self.backup_dir = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def print_header(self):
        """Imprime cabeçalho do script"""
        print("=" * 70)
        print("🚀 CONFIGURAÇÃO DE RELATÓRIOS AVANÇADOS")
        print("📊 Sistema de Analytics Administrativos")
        print("=" * 70)
        print()
    
    def create_backup(self):
        """Cria backup dos arquivos importantes"""
        print("📋 Criando backup dos arquivos existentes...")
        
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            
            for file in ['admin_pages.py', 'main.py']:
                if os.path.exists(file):
                    shutil.copy2(file, os.path.join(self.backup_dir, file))
                    print(f"✅ Backup criado: {file}")
            
            print(f"📁 Backup salvo em: {self.backup_dir}")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao criar backup: {e}")
            return False
    
    def check_files(self):
        """Verifica se arquivos necessários estão presentes"""
        print("🔍 Verificando arquivos necessários...")
        
        missing = []
        present = []
        
        for file in self.required_files:
            if os.path.exists(file):
                present.append(file)
                print(f"✅ Encontrado: {file}")
            else:
                missing.append(file)
                print(f"❌ Faltando: {file}")
        
        if missing:
            print(f"\n⚠️  Arquivos faltando: {len(missing)}")
            print("📝 Certifique-se de ter todos os arquivos do sistema de relatórios")
            return False
        
        print(f"\n✅ Todos os {len(present)} arquivos necessários estão presentes!")
        return True
    
    def install_packages(self):
        """Instala pacotes Python necessários"""
        print("📦 Instalando dependências para relatórios...")
        
        # Verificar se já estão instalados
        missing_packages = []
        
        for package in self.required_packages:
            package_name = package.split('>=')[0]
            try:
                __import__(package_name)
                print(f"✅ Já instalado: {package_name}")
            except ImportError:
                missing_packages.append(package)
        
        if not missing_packages:
            print("✅ Todas as dependências já estão instaladas!")
            return True
        
        print(f"📥 Instalando {len(missing_packages)} pacotes...")
        
        for package in missing_packages:
            try:
                print(f"⏳ Instalando {package}...")
                subprocess.check_call([
                    sys.executable, '-m', 'pip', 'install', package
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"✅ Instalado: {package}")
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Erro ao instalar {package}: {e}")
                return False
        
        print("✅ Todas as dependências foram instaladas!")
        return True
    
    def update_admin_pages(self):
        """Atualiza admin_pages.py para incluir relatórios avançados"""
        print("🔧 Atualizando admin_pages.py...")
        
        try:
            with open('admin_pages.py', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verificar se já tem a integração
            if 'advanced_reports' in content and 'render_enhanced_reports_section' in content:
                print("✅ admin_pages.py já tem integração de relatórios!")
                return True
            
            # Atualizar navegação - adicionar advanced_reports
            old_nav_list = '["dashboard", "users", "files", "reports", "logs"]'
            new_nav_list = '["dashboard", "users", "files", "reports", "advanced_reports", "logs"]'
            
            if old_nav_list in content:
                content = content.replace(old_nav_list, new_nav_list)
                print("✅ Lista de navegação atualizada")
            
            # Atualizar format_func
            old_format = '"reports": "📈 Relatórios",'
            new_format = '''                "reports": "📈 Relatórios Básicos",
                "advanced_reports": "📊 Relatórios Avançados",'''
            
            if old_format in content:
                content = content.replace(old_format, new_format)
                print("✅ Labels de navegação atualizadas")
            
            # Adicionar elif para advanced_reports
            old_elif = '''elif page == 'reports':
            render_reports_section(username, user_manager)
        elif page == 'logs':'''
            
            new_elif = '''elif page == 'reports':
            render_reports_section(username, user_manager)
        elif page == 'advanced_reports':
            render_advanced_reports_section(username, user_manager)
        elif page == 'logs':'''
            
            if old_elif in content:
                content = content.replace(old_elif, new_elif)
                print("✅ Roteamento de páginas atualizado")
            
            # Adicionar função render_advanced_reports_section
            function_to_add = '''

def render_advanced_reports_section(username: str, user_manager=None):
    """Renderiza seção de relatórios avançados com gráficos"""
    
    try:
        # Importar sistema de relatórios avançados
        from enhanced_admin_reports import render_enhanced_reports_section
        from database import DatabaseManager
        from config import Config
        
        # Inicializar database manager
        db_manager = DatabaseManager(Config.DATABASE_URL)
        
        # Renderizar relatórios avançados
        render_enhanced_reports_section(username, user_manager, db_manager)
        
    except ImportError as import_error:
        logger.error(f"Enhanced reports not available: {import_error}")
        st.error("❌ Sistema de relatórios avançados não disponível")
        st.info("Execute: pip install plotly pandas numpy matplotlib seaborn")
        
        # Mostrar instruções de instalação
        st.code("pip install plotly>=5.15.0 pandas>=1.5.0 numpy>=1.24.0")
        
        # Fallback para relatórios básicos
        st.warning("📊 Usando relatórios básicos como alternativa")
        render_reports_section(username, user_manager)
        
    except Exception as e:
        logger.error(f"Advanced reports error: {e}")
        st.error(f"❌ Erro nos relatórios avançados: {e}")
        
        # Informações de debug
        with st.expander("🔍 Informações de Debug"):
            st.write("**Erro:**", str(e))
            st.write("**Usuário:**", username)
            st.write("**Timestamp:**", datetime.now().isoformat())
        
        # Tentar relatórios básicos como fallback
        st.warning("📊 Tentando carregar relatórios básicos...")
        try:
            render_reports_section(username, user_manager)
        except Exception as fallback_error:
            st.error(f"❌ Erro também nos relatórios básicos: {fallback_error}")
'''
            
            # Adicionar função antes do final do arquivo
            if not 'render_advanced_reports_section' in content:
                # Encontrar local para inserir (antes do último logger.info)
                last_logger = content.rfind('logger.info("✅')
                if last_logger != -1:
                    content = content[:last_logger] + function_to_add + '\n\n' + content[last_logger:]
                else:
                    # Se não encontrar, adicionar no final
                    content += function_to_add
                
                print("✅ Função de relatórios avançados adicionada")
            
            # Salvar arquivo atualizado
            with open('admin_pages.py', 'w', encoding='utf-8') as f:
                f.write(content)
            
            print("✅ admin_pages.py atualizado com sucesso!")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao atualizar admin_pages.py: {e}")
            return False
    
    def update_dashboard_actions(self):
        """Adiciona botão para relatórios avançados no dashboard"""
        print("🎛️  Atualizando dashboard com link para relatórios...")
        
        try:
            with open('admin_pages.py', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Procurar pela função render_admin_dashboard
            if 'render_admin_dashboard' in content:
                # Adicionar botão destacado para relatórios avançados
                dashboard_addition = '''        
        # Link destacado para relatórios avançados
        st.markdown("---")
        st.info("💡 **Novo!** Acesse os **Relatórios Avançados** para análises detalhadas com gráficos interativos!")
        
        if st.button("🚀 Ir para Relatórios Avançados", type="primary", use_container_width=True):
            st.session_state.admin_current_page = "advanced_reports"
            st.rerun()'''
            
                # Encontrar local para inserir (antes do except final da função)
                dashboard_end = content.find('except Exception as e:', content.find('render_admin_dashboard'))
                if dashboard_end != -1:
                    # Inserir antes do except
                    content = content[:dashboard_end] + dashboard_addition + '\n        \n    ' + content[dashboard_end:]
                    
                    with open('admin_pages.py', 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    print("✅ Dashboard atualizado com link para relatórios!")
                    return True
            
            print("⚠️  Dashboard não pôde ser atualizado automaticamente")
            return True  # Não é crítico
            
        except Exception as e:
            print(f"⚠️  Erro ao atualizar dashboard: {e}")
            return True  # Não é crítico
    
    def test_integration(self):
        """Testa se a integração está funcionando"""
        print("🧪 Testando integração...")
        
        try:
            # Testar imports básicos
            import enhanced_admin_reports
            print("✅ enhanced_admin_reports importado")
            
            import admin_reports_data
            print("✅ admin_reports_data importado")
            
            import reports_config
            print("✅ reports_config importado")
            
            # Testar dependências
            import plotly
            print("✅ plotly importado")
            
            import pandas
            print("✅ pandas importado")
            
            import numpy
            print("✅ numpy importado")
            
            # Testar função principal
            from enhanced_admin_reports import render_enhanced_reports_section
            print("✅ Função principal dos relatórios disponível")
            
            return True
            
        except ImportError as e:
            print(f"❌ Erro de importação: {e}")
            return False
        except Exception as e:
            print(f"❌ Erro no teste: {e}")
            return False
    
    def show_success_message(self):
        """Mostra mensagem de sucesso"""
        print("\n" + "=" * 70)
        print("🎉 INTEGRAÇÃO DOS RELATÓRIOS CONCLUÍDA COM SUCESSO!")
        print("=" * 70)
        print()
        print("📋 PRÓXIMOS PASSOS:")
        print("1. 🔄 Reinicie sua aplicação Streamlit")
        print("2. 🔐 Faça login como administrador")
        print("3. 🛡️  Acesse a aba 'Administração'")
        print("4. 📊 Clique em 'Relatórios Avançados'")
        print()
        print("🚀 RECURSOS DISPONÍVEIS:")
        print("• 📊 Dashboard Geral com métricas avançadas")
        print("• 👥 Analytics detalhados de Usuários")
        print("• 📁 Analytics completos de Arquivos")
        print("• 🔐 Analytics de Segurança e MFA")
        print("• 📈 Analytics de Performance do Sistema")
        print("• 🎯 Centro de Ações Rápidas")
        print("• 🔍 Filtros e períodos personalizáveis")
        print("• 📈 Gráficos interativos com Plotly")
        print()
        print("💡 DICA: Use os filtros de período para análises específicas!")
        print()
        print("=" * 70)
    
    def run(self):
        """Executa todo o processo de configuração"""
        self.print_header()
        
        # Passo 1: Verificar arquivos
        if not self.check_files():
            print("\n❌ Configuração abortada - arquivos faltando")
            print("📝 Certifique-se de ter todos os arquivos do sistema de relatórios")
            return False
        
        print()
        
        # Passo 2: Criar backup
        if not self.create_backup():
            print("\n⚠️  Continuando sem backup...")
        
        print()
        
        # Passo 3: Instalar dependências
        if not self.install_packages():
            print("\n❌ Configuração abortada - erro nas dependências")
            return False
        
        print()
        
        # Passo 4: Atualizar admin_pages.py
        if not self.update_admin_pages():
            print("\n❌ Configuração abortada - erro ao atualizar admin_pages.py")
            return False
        
        print()
        
        # Passo 5: Atualizar dashboard
        self.update_dashboard_actions()
        
        print()
        
        # Passo 6: Testar integração
        if not self.test_integration():
            print("\n⚠️  Integração pode ter problemas - verifique logs")
            print("💡 Mesmo assim, tente executar o sistema")
        
        print()
        
        # Sucesso!
        self.show_success_message()
        return True

def main():
    """Função principal"""
    setup = ReportsSetup()
    success = setup.run()
    
    if not success:
        print("\n" + "=" * 50)
        print("❌ CONFIGURAÇÃO NÃO CONCLUÍDA")
        print("📞 Verifique os erros acima e tente novamente")
        print("=" * 50)
        return False
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Configuração cancelada pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro crítico: {e}")
        sys.exit(1)
