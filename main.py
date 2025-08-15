"""
MAIN.PY - VERSÃO CORRIGIDA COM PAINEL ADMINISTRATIVO COMPLETO
Inclui correção do erro "too many values to unpack" e proteção Path Traversal
"""
import streamlit as st
import logging
from datetime import datetime

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Função principal com sistema administrativo completo"""
    try:
        # Configurações iniciais básicas
        st.set_page_config(
            page_title="Sistema de Arquivos",
            page_icon="📁",
            layout="wide",
            initial_sidebar_state="auto"
        )

        # Importações com tratamento de erro
        try:
            from config import Config, setup_app_security
            from database import DatabaseManager
            from s3_manager import S3Manager
            from session_manager import SessionManager
            from mfa import MFAManager
            from ui_components import UIComponents
            from pages import LoginPage, MainApplicationPage, TemporaryLinkAccessPage
            from user_management import UserManager

            logger.info("✅ Core modules loaded successfully")

        except ImportError as e:
            st.error(f"❌ Erro ao carregar módulos principais: {e}")
            st.error("Verifique se todos os arquivos estão presentes")
            logger.error(f"Import error: {e}")
            st.stop()

        # Validação de ambiente
        try:
            if not Config.validate_environment():
                st.error("❌ Configuração de ambiente inválida")
                st.stop()
        except Exception as e:
            st.error(f"❌ Erro na validação de ambiente: {e}")
            logger.error(f"Environment validation error: {e}")
            st.stop()

        # Inicialização de sistemas
        try:
            # Sistema de segurança
            security_setup = setup_app_security()
            if security_setup and security_setup.get('security'):
                security = security_setup['security']
                if 'security_middleware' in security:
                    security['security_middleware']()

            logger.info("✅ Security system initialized")

        except Exception as e:
            logger.warning(f"Security system error (continuing anyway): {e}")

        try:
            # Gerenciadores principais
            db_manager = DatabaseManager(Config.DATABASE_URL)
            s3_manager = S3Manager(
                Config.AWS_ACCESS_KEY_ID,
                Config.AWS_SECRET_ACCESS_KEY,
                Config.AWS_REGION,
                Config.S3_BUCKET
            )

            logger.info("✅ Core managers initialized")

        except Exception as e:
            st.error(f"❌ Erro ao inicializar gerenciadores: {e}")
            logger.error(f"Manager initialization error: {e}")
            st.stop()

        try:
            # Inicializar banco de dados
            db_manager.init_database()
            logger.info("✅ Database initialized")

        except Exception as e:
            st.error(f"❌ Erro ao inicializar banco: {e}")
            logger.error(f"Database initialization error: {e}")
            st.stop()

        try:
            # Sistemas auxiliares
            session_manager = SessionManager(db_manager)
            mfa_manager = MFAManager(db_manager)
            ui_components = UIComponents(Config)

            # Sistema de usuários com inicialização segura
            user_manager = UserManager(db_manager)
            user_manager.init_user_tables()
            logger.info("✅ User management system initialized")

            logger.info("✅ Auxiliary systems initialized")

        except Exception as e:
            logger.error(f"Error initializing auxiliary systems: {e}")
            # Usar sistemas básicos se houver erro
            session_manager = None
            mfa_manager = None
            ui_components = None
            user_manager = None

        # Inicialização de sessão
        try:
            if session_manager:
                session_manager.init_session_state()
            else:
                # Inicialização manual de emergência
                if 'authenticated' not in st.session_state:
                    st.session_state.authenticated = False
                if 'username' not in st.session_state:
                    st.session_state.username = None
                if 'awaiting_mfa' not in st.session_state:
                    st.session_state.awaiting_mfa = False

            logger.info("✅ Session state initialized")

        except Exception as e:
            logger.warning(f"Session initialization error: {e}")
            # Fallback manual
            if 'authenticated' not in st.session_state:
                st.session_state.authenticated = False
            if 'username' not in st.session_state:
                st.session_state.username = None
            if 'awaiting_mfa' not in st.session_state:
                st.session_state.awaiting_mfa = False

        # Roteamento de páginas
        try:
            # Verificar link temporário PRIMEIRO
            query_params = st.query_params
            temp_link = query_params.get("temp_link")

            if temp_link:
                try:
                    temp_page = TemporaryLinkAccessPage(db_manager, s3_manager, ui_components)
                    temp_page.render(temp_link)
                    return
                except Exception as e:
                    st.error(f"Erro na página de link temporário: {e}")
                    logger.error(f"Temporary link page error: {e}")

            # Verificar sessão persistente
            try:
                if session_manager and session_manager.check_persistent_session():
                    logger.info(f"Persistent session found for: {st.session_state.username}")
            except Exception as e:
                logger.warning(f"Persistent session check error: {e}")

            # Lógica de autenticação
            if not st.session_state.get('authenticated', False):
                # Página de login
                try:
                    if all([db_manager, session_manager, mfa_manager, ui_components]):
                        login_page = LoginPage(db_manager, session_manager, mfa_manager, ui_components)
                        login_page.render()
                    else:
                        # Login de emergência
                        render_emergency_login(db_manager)

                except Exception as e:
                    st.error(f"❌ Erro na página de login: {e}")
                    logger.error(f"Login page error: {e}")

                    # Fallback: Login básico de emergência
                    render_emergency_login(db_manager)
            else:
                # Aplicação principal COM PAINEL ADMIN COMPLETO
                try:
                    # Carregar aplicação com admin completo
                    main_app = CompleteAdminApplicationPage(
                        db_manager, s3_manager, session_manager, mfa_manager,
                        ui_components, user_manager
                    )
                    main_app.render(st.session_state.username)

                except Exception as e:
                    st.error(f"❌ Erro na aplicação principal: {e}")
                    logger.error(f"Main application error: {e}")

                    # Fallback para aplicação básica
                    try:
                        basic_app = MainApplicationPage(
                            db_manager, s3_manager, session_manager, mfa_manager, ui_components
                        )
                        basic_app.render(st.session_state.username)
                    except Exception as basic_error:
                        st.error(f"❌ Erro na aplicação básica: {basic_error}")

                        # Último recurso - logout de emergência
                        if st.button("🚪 Logout (Emergência)"):
                            for key in list(st.session_state.keys()):
                                del st.session_state[key]
                            st.rerun()

        except Exception as e:
            st.error(f"❌ Erro crítico no roteamento: {e}")
            logger.error(f"Critical routing error: {e}")

            # Reset completo em caso de erro crítico
            if st.button("🔄 Reiniciar Sistema"):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()

    except Exception as e:
        st.error(f"❌ Erro crítico na aplicação: {e}")
        logger.error(f"Critical application error: {e}")

        st.error("Sistema encontrou um erro crítico.")
        st.info("Tente recarregar a página ou entre em contato com o suporte.")


def render_emergency_login(db_manager):
    """Login de emergência caso o sistema principal falhe"""
    try:
        st.title("🔐 Login de Emergência")
        st.warning("Sistema básico de login ativo")

        with st.form("emergency_login"):
            username = st.text_input("Usuário", placeholder="Digite seu usuário")
            password = st.text_input("Senha", type="password", placeholder="Digite sua senha")
            submit = st.form_submit_button("Entrar")

            if submit and username and password:
                try:
                    authenticated, has_mfa = db_manager.authenticate_user(username, password)

                    if authenticated:
                        if has_mfa:
                            st.warning("⚠️ MFA detectado mas não disponível no modo emergência")
                            st.info("Sistema será carregado sem verificação MFA")

                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.session_state.awaiting_mfa = False

                        st.success("✅ Login realizado!")
                        st.rerun()
                    else:
                        st.error("❌ Credenciais inválidas!")

                except Exception as e:
                    st.error(f"❌ Erro na autenticação: {e}")

    except Exception as e:
        st.error(f"❌ Erro no login de emergência: {e}")


class CompleteAdminApplicationPage:
    """Aplicação principal com sistema administrativo COMPLETO"""

    def __init__(self, db_manager, s3_manager, session_manager, mfa_manager, ui_components, user_manager):
        self.db_manager = db_manager
        self.s3_manager = s3_manager
        self.session_manager = session_manager
        self.mfa_manager = mfa_manager
        self.ui = ui_components
        self.user_manager = user_manager

        # Inicializar páginas auxiliares
        try:
            from pages import TemporaryLinksPage, MFASetupPage
            self.temp_links_page = TemporaryLinksPage(db_manager, ui_components)
            self.mfa_setup_page = MFASetupPage(mfa_manager, ui_components)
        except Exception as e:
            logger.warning(f"Auxiliary pages not available: {e}")
            self.temp_links_page = None
            self.mfa_setup_page = None

    def render(self, username: str):
        """Renderiza aplicação principal com admin completo"""
        try:
            self.ui.display_header_with_logo(
                f"Sistema de Arquivos - {username}",
                "Gerenciamento Seguro de Arquivos"
            )

            self._render_sidebar(username)

            # Verificar se é admin para mostrar aba administrativa
            is_admin = self._check_admin_permissions(username)

            # Tabs principais - admin condicional
            if is_admin:
                tab1, tab2, tab3, tab4, tab5 = st.tabs([
                    "📤 Upload",
                    "📥 Meus Arquivos",
                    "🔗 Links Temporários",
                    "🔐 Segurança",
                    "🛡️ Administração"
                ])

                with tab5:
                    self._render_admin_tab(username)
            else:
                tab1, tab2, tab3, tab4 = st.tabs([
                    "📤 Upload",
                    "📥 Meus Arquivos",
                    "🔗 Links Temporários",
                    "🔐 Segurança"
                ])

            with tab1:
                self._render_upload_tab(username)

            with tab2:
                self._render_files_tab(username)

            with tab3:
                self._render_temp_links_tab(username)

            with tab4:
                self._render_security_tab(username)

        except Exception as e:
            st.error(f"❌ Erro ao renderizar aplicação: {e}")
            logger.error(f"Application render error: {e}")

    def _check_admin_permissions(self, username: str) -> bool:
        """Verifica se usuário tem permissões administrativas"""
        try:
            # Método 1: Usar user_manager se disponível
            if self.user_manager and hasattr(self.user_manager, 'get_user_role'):
                role = self.user_manager.get_user_role(username)
                if role in ['admin', 'super_admin']:
                    return True

            # Método 2: Verificar diretamente no banco
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            try:
                # Tentar tabela estendida primeiro
                cursor.execute("SELECT role FROM users_extended WHERE username = %s", (username,))
                result = cursor.fetchone()

                if result and result[0] in ['admin', 'super_admin']:
                    cursor.close()
                    conn.close()
                    return True
            except:
                pass

            # Método 3: Verificar se username contém 'admin' (fallback)
            if 'admin' in username.lower():
                cursor.close()
                conn.close()
                return True

            cursor.close()
            conn.close()
            return False

        except Exception as e:
            logger.error(f"Error checking admin permissions: {e}")
            # Em caso de erro, ser conservador e negar acesso
            return False

    def _render_sidebar(self, username: str):
        """Renderiza sidebar"""
        try:
            with st.sidebar:
                self.ui.display_sidebar_logo()

                # Informações do usuário
                try:
                    _, mfa_enabled = self.mfa_manager.get_user_mfa_info(username)
                except:
                    mfa_enabled = None

                has_persistent_session = bool(st.session_state.get('session_token'))
                self.ui.display_user_info(username, mfa_enabled, has_persistent_session)

                # Mostrar se é admin
                if self._check_admin_permissions(username):
                    st.sidebar.success("🛡️ Administrador")

                st.sidebar.markdown("---")

                # Logout
                if st.button("🚪 Logout", type="secondary", use_container_width=True):
                    try:
                        self.session_manager.perform_logout()
                    except:
                        # Logout de emergência
                        for key in list(st.session_state.keys()):
                            del st.session_state[key]
                    st.rerun()

                self.ui.display_footer()

        except Exception as e:
            st.sidebar.error(f"Erro na sidebar: {e}")

    def _render_upload_tab(self, username: str):
        """Renderiza aba de upload com sistema melhorado"""
        try:
            # Tentar sistema avançado primeiro, fallback para básico
            try:
                from concurrent_upload_ui import render_concurrent_upload_section
                render_concurrent_upload_section(self.s3_manager, self.db_manager, username)

            except ImportError:
                logger.warning("Concurrent upload system not available - using basic upload")
                self._render_basic_upload_tab(username)

            except Exception as e:
                logger.error(f"Concurrent upload error: {e}")
                st.warning("⚠️ Erro no sistema avançado, usando upload básico")
                self._render_basic_upload_tab(username)

        except Exception as e:
            st.error(f"❌ Erro na aba de upload: {e}")
            logger.error(f"Upload tab error: {e}")

    def _render_basic_upload_tab(self, username: str):
        """Upload básico como fallback"""
        try:
            st.header("📤 Upload de Arquivo")

            uploaded_file = st.file_uploader("Escolha um arquivo:", type=None)

            if uploaded_file is not None:
                # Informações do arquivo
                st.write(f"**Nome:** {uploaded_file.name}")
                st.write(f"**Tamanho:** {uploaded_file.size:,} bytes")
                st.write(f"**Tipo:** {uploaded_file.type or 'Desconhecido'}")

                if st.button("🚀 Fazer Upload", type="primary"):
                    try:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        file_key = f"{username}/{timestamp}_{uploaded_file.name}"

                        with st.spinner("Fazendo upload..."):
                            # Upload com proteção Path Traversal
                            success = self.s3_manager.upload_file(uploaded_file, file_key)
                            
                            if success:
                                # Salvar metadados
                                self.db_manager.save_file_metadata(
                                    file_key=file_key,
                                    original_name=uploaded_file.name,
                                    file_size=uploaded_file.size,
                                    username=username,
                                    mime_type=uploaded_file.type or "application/octet-stream"
                                )

                                st.success("✅ Upload concluído!")
                                st.balloons()
                            else:
                                st.error("❌ Falha no upload")

                    except Exception as e:
                        st.error(f"❌ Erro: {str(e)}")

        except Exception as e:
            st.error(f"❌ Erro no upload básico: {e}")

    def _render_files_tab(self, username: str):
        """Renderiza aba de arquivos - CORRIGIDO PARA MÚLTIPLOS FORMATOS"""
        try:
            st.header("📥 Meus Arquivos")

            # Obter arquivos
            files = self.db_manager.get_user_files(username)

            if not files:
                st.info("📂 Nenhum arquivo encontrado")

                # Seção de ajuda para arquivos não aparecendo
                with st.expander("🔧 Arquivos não aparecem? Clique aqui", expanded=False):
                    st.write("""
                    **Possíveis soluções:**
                    1. Aguarde alguns segundos e recarregue a página
                    2. Verifique se o upload foi concluído com sucesso
                    3. Entre em contato com o administrador se o problema persistir
                    """)

                    if st.button("🔄 Recarregar Lista de Arquivos"):
                        st.rerun()

                return

            st.write(f"📊 **Total:** {len(files)} arquivos")
            st.markdown("---")

            # Listar arquivos - CORREÇÃO DO ERRO AQUI
            for idx, file_tuple in enumerate(files):
                try:
                    # Desempacotar com segurança - aceita diferentes tamanhos
                    if len(file_tuple) >= 5:
                        file_key = file_tuple[0]
                        original_name = file_tuple[1]
                        file_size = file_tuple[2]
                        uploaded_at = file_tuple[3]
                        downloaded = file_tuple[4]
                        
                        # Campos opcionais das novas colunas de segurança
                        is_safe = file_tuple[5] if len(file_tuple) > 5 else True
                        sanitized_name = file_tuple[6] if len(file_tuple) > 6 else original_name
                    else:
                        # Formato antigo com menos campos
                        file_key = file_tuple[0]
                        original_name = file_tuple[1]
                        file_size = file_tuple[2] if len(file_tuple) > 2 else 0
                        uploaded_at = file_tuple[3] if len(file_tuple) > 3 else None
                        downloaded = file_tuple[4] if len(file_tuple) > 4 else False
                        is_safe = True
                        sanitized_name = original_name

                    with st.container():
                        col1, col2, col3, col4 = st.columns([3, 1, 1, 1])

                        with col1:
                            # Mostrar ícone de segurança se arquivo não for seguro
                            if not is_safe:
                                st.write(f"⚠️ **📄 {sanitized_name}**")
                            else:
                                st.write(f"**📄 {original_name}**")
                            
                            st.caption(f"📊 {file_size:,} bytes")
                            if uploaded_at:
                                st.caption(f"📅 {uploaded_at.strftime('%d/%m/%Y %H:%M')}")

                        with col2:
                            if downloaded:
                                st.success("✅ Baixado")
                            else:
                                st.info("⏳ Disponível")

                        with col3:
                            if st.button("📥 Download", key=f"dl_{idx}", use_container_width=True):
                                self._handle_download(file_key, original_name, idx, username)

                        with col4:
                            if st.button("🗑️ Deletar", key=f"del_{idx}", type="secondary", use_container_width=True):
                                st.session_state[f"confirm_delete_{file_key}"] = True

                            if st.session_state.get(f"confirm_delete_{file_key}", False):
                                st.warning("⚠️ Confirmar?")
                                col_yes, col_no = st.columns(2)

                                with col_yes:
                                    if st.button("✅ Sim", key=f"yes_{idx}", use_container_width=True):
                                        self._handle_delete(file_key, idx, username)

                                with col_no:
                                    if st.button("❌ Não", key=f"no_{idx}", use_container_width=True):
                                        del st.session_state[f"confirm_delete_{file_key}"]
                                        st.rerun()

                        st.divider()

                except Exception as file_error:
                    logger.error(f"Error processing file {idx}: {file_error}")
                    st.error(f"Erro ao processar arquivo {idx}")

        except Exception as e:
            st.error(f"❌ Erro ao carregar arquivos: {e}")
            logger.error(f"Files tab error: {e}")

    def _handle_download(self, file_key: str, original_name: str, idx: int, username: str):
        """Trata download de arquivo"""
        try:
            with st.spinner("Baixando..."):
                file_data = self.s3_manager.download_file(file_key)

                if file_data:
                    self.db_manager.record_download(username, file_key, "127.0.0.1")

                    st.download_button(
                        "📥 Clique para Baixar",
                        data=file_data,
                        file_name=original_name,
                        key=f"dlbtn_{idx}",
                        use_container_width=True
                    )
                    st.success("✅ Download registrado!")
                    st.rerun()
                else:
                    st.error("❌ Erro no download")

        except Exception as e:
            st.error(f"❌ Erro no download: {e}")

    def _handle_delete(self, file_key: str, idx: int, username: str):
        """Trata deleção de arquivo"""
        try:
            with st.spinner("Deletando..."):
                s3_deleted = self.s3_manager.delete_file(file_key)
                db_deleted = self.db_manager.delete_file_metadata(file_key, username)

                if db_deleted:
                    st.success("✅ Arquivo deletado!")
                    if f"confirm_delete_{file_key}" in st.session_state:
                        del st.session_state[f"confirm_delete_{file_key}"]
                    st.rerun()
                else:
                    st.error("❌ Erro ao deletar")

        except Exception as e:
            st.error(f"❌ Erro na deleção: {e}")

    def _render_temp_links_tab(self, username: str):
        """Renderiza aba de links temporários"""
        try:
            if self.temp_links_page:
                self.temp_links_page.render(username)
            else:
                st.info("⚠️ Sistema de links temporários não disponível")

        except Exception as e:
            st.error(f"❌ Erro nos links temporários: {e}")

    def _render_security_tab(self, username: str):
        """Renderiza aba de segurança"""
        try:
            if self.mfa_setup_page:
                self.mfa_setup_page.render(username)
            else:
                st.info("⚠️ Sistema MFA não disponível")

        except Exception as e:
            st.error(f"❌ Erro na aba de segurança: {e}")

    def _render_admin_tab(self, username: str):
        """Renderiza aba administrativa COMPLETA com TODOS os recursos"""
        try:
            # Verificar permissões novamente
            if not self._check_admin_permissions(username):
                st.error("❌ Acesso negado. Apenas administradores podem acessar esta seção.")
                return

            # Importação e renderização do painel admin
            try:
                from admin_pages import render_admin_panel
                render_admin_panel(username, self.user_manager)

            except ImportError as import_error:
                logger.warning(f"admin_pages module not found: {import_error}")
                st.error("❌ Módulo admin_pages não encontrado")
                st.info("Verifique se o arquivo admin_pages.py está presente no projeto")
                self._render_admin_fallback(username)

            except Exception as admin_error:
                logger.error(f"Admin panel error: {admin_error}")
                st.error(f"❌ Erro no painel admin: {admin_error}")
                st.warning("Tentando carregar painel básico...")
                self._render_admin_fallback(username)

        except Exception as e:
            st.error(f"❌ Erro na aba admin: {e}")
            logger.error(f"Admin tab error: {e}")

    def _render_admin_fallback(self, username: str):
        """Renderiza versão básica do painel admin como fallback"""
        try:
            st.header("🛡️ Administração - Modo Básico")
            st.warning("⚠️ Painel avançado indisponível")

            # Estatísticas básicas
            try:
                conn = self.db_manager.get_connection()
                cursor = conn.cursor()

                # Contar usuários
                try:
                    cursor.execute("SELECT COUNT(*) FROM users_extended WHERE is_active = TRUE")
                    user_count = cursor.fetchone()[0] or 0
                except:
                    cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
                    user_count = cursor.fetchone()[0] or 0

                # Contar arquivos
                cursor.execute("SELECT COUNT(*), SUM(file_size) FROM files")
                file_stats = cursor.fetchone()
                file_count = file_stats[0] or 0
                total_size = file_stats[1] or 0

                # Mostrar métricas
                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("👥 Usuários", f"{user_count:,}")

                with col2:
                    st.metric("📄 Arquivos", f"{file_count:,}")

                with col3:
                    size_gb = total_size / (1024**3) if total_size else 0
                    st.metric("💾 Armazenamento", f"{size_gb:.2f} GB")

                cursor.close()
                conn.close()

            except Exception as stats_error:
                st.error(f"Erro ao carregar estatísticas: {stats_error}")

            # Ações básicas disponíveis
            st.markdown("---")
            st.subheader("⚡ Ações Disponíveis")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("📋 Listar Usuários", use_container_width=True):
                    self._show_basic_user_list()

            with col2:
                if st.button("📁 Listar Todos os Arquivos", use_container_width=True):
                    self._show_basic_file_list()

        except Exception as e:
            st.error(f"❌ Erro no admin básico: {e}")

    def _show_basic_user_list(self):
        """Lista básica de usuários"""
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    SELECT username, full_name, email, role, status, created_at
                    FROM users_extended
                    WHERE is_active = TRUE
                    ORDER BY created_at DESC
                    LIMIT 50
                """)
            except:
                cursor.execute("""
                    SELECT username, username as full_name, email, 'user' as role,
                           CASE WHEN is_active THEN 'active' ELSE 'inactive' END as status,
                           created_at
                    FROM users
                    WHERE is_active = TRUE
                    ORDER BY created_at DESC
                    LIMIT 50
                """)

            users = cursor.fetchall()
            cursor.close()
            conn.close()

            if users:
                st.write(f"**📊 {len(users)} usuários encontrados**")

                for user in users:
                    with st.container():
                        col1, col2, col3 = st.columns([2, 1, 1])

                        with col1:
                            st.write(f"**{user[1] or user[0]}**")
                            st.caption(f"@{user[0]} - {user[2] or 'Sem email'}")

                        with col2:
                            st.write(f"🎭 {user[3] or 'user'}")
                            st.caption(f"📊 {user[4] or 'active'}")

                        with col3:
                            if user[5]:
                                st.caption(f"📅 {user[5].strftime('%d/%m/%Y')}")

                        st.divider()
            else:
                st.info("Nenhum usuário encontrado")

        except Exception as e:
            st.error(f"Erro ao listar usuários: {e}")

    def _show_basic_file_list(self):
        """Lista básica de todos os arquivos"""
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT original_name, uploaded_by, file_size, uploaded_at, file_key
                FROM files
                ORDER BY uploaded_at DESC
                LIMIT 50
            """)

            files = cursor.fetchall()
            cursor.close()
            conn.close()

            if files:
                st.write(f"**📊 {len(files)} arquivos encontrados (últimos 50)**")

                for file_data in files:
                    with st.container():
                        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

                        with col1:
                            st.write(f"**📄 {file_data[0]}**")
                            st.caption(f"👤 {file_data[1] or 'Desconhecido'}")

                        with col2:
                            size_mb = (file_data[2] or 0) / (1024*1024)
                            st.write(f"📊 {size_mb:.1f} MB")

                        with col3:
                            if file_data[3]:
                                st.caption(f"📅 {file_data[3].strftime('%d/%m/%Y')}")

                        with col4:
                            if st.button("🗑️", key=f"admin_del_{file_data[4]}", help="Deletar"):
                                try:
                                    # Deletar do S3 e banco
                                    self.s3_manager.delete_file(file_data[4])

                                    conn_del = self.db_manager.get_connection()
                                    cursor_del = conn_del.cursor()
                                    cursor_del.execute("DELETE FROM files WHERE file_key = %s", (file_data[4],))
                                    conn_del.commit()
                                    cursor_del.close()
                                    conn_del.close()

                                    st.success("✅ Arquivo deletado!")
                                    st.rerun()
                                except Exception as del_error:
                                    st.error(f"Erro ao deletar: {del_error}")

                        st.divider()
            else:
                st.info("Nenhum arquivo encontrado")

        except Exception as e:
            st.error(f"Erro ao listar arquivos: {e}")


# Ponto de entrada seguro
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"❌ Erro crítico na inicialização: {e}")
        st.error("Tente recarregar a página")
        logger.error(f"Critical startup error: {e}")


# Log de inicialização
logger.info("✅ Main application loaded with complete admin functionality")
