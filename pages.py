"""
Módulo com as páginas da aplicação - VERSÃO SEGURA COM PROTEÇÃO IDOR
Todas as operações validam propriedade e autorização
"""
import streamlit as st
import logging
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict, Any
import hashlib
import secrets

logger = logging.getLogger(__name__)


class SecurityValidator:
    """Classe auxiliar para validações de segurança IDOR"""
    
    @staticmethod
    def validate_user_context(session_username: str, requested_username: str) -> bool:
        """Valida se o usuário da sessão corresponde ao solicitado"""
        if not session_username or not requested_username:
            logger.error("Missing username in validation")
            return False
        
        if session_username != requested_username:
            logger.warning(f"IDOR attempt: {session_username} trying to access {requested_username}")
            return False
        
        return True
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 255) -> str:
        """Sanitiza entrada do usuário"""
        if not input_str:
            return ""
        
        # Remover caracteres perigosos
        sanitized = input_str.strip()
        sanitized = sanitized[:max_length]
        
        # Remover caracteres de controle
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32)
        
        return sanitized


class LoginPage:
    """Página de login com MFA e proteção contra ataques"""
    
    def __init__(self, db_manager, session_manager, mfa_manager, ui_components):
        self.db_manager = db_manager
        self.session_manager = session_manager
        self.mfa_manager = mfa_manager
        self.ui = ui_components
        self.security = SecurityValidator()
        
        # Rate limiting para login
        if 'login_attempts' not in st.session_state:
            st.session_state.login_attempts = {}
    
    def render(self):
        """Renderiza a página de login"""
        self.ui.display_header_with_logo(
            "🔐 Pluxee",
            f"Gerenciador de Arquivos - {self.ui.config.COMPANY_NAME}"
        )

        st.markdown("---")

        if not st.session_state.awaiting_mfa:
            self._render_login_form()
        else:
            self._render_mfa_form()

        self._render_footer()

    def _check_rate_limit(self, username: str) -> bool:
        """Verifica rate limiting para tentativas de login"""
        current_time = datetime.now()
        
        if username in st.session_state.login_attempts:
            attempts = st.session_state.login_attempts[username]
            
            # Limpar tentativas antigas (mais de 15 minutos)
            cutoff = current_time - timedelta(minutes=15)
            attempts = [t for t in attempts if t > cutoff]
            st.session_state.login_attempts[username] = attempts
            
            # Verificar se excedeu limite
            if len(attempts) >= 5:
                st.error("⚠️ Muitas tentativas. Aguarde 15 minutos.")
                return False
        
        return True

    def _record_login_attempt(self, username: str):
        """Registra tentativa de login"""
        if username not in st.session_state.login_attempts:
            st.session_state.login_attempts[username] = []
        
        st.session_state.login_attempts[username].append(datetime.now())

    def _render_login_form(self):
        """Renderiza formulário de login com proteção"""
        username, password, remember_me = self.ui.show_login_form(
            None, 
            self.session_manager.is_cookies_available()
        )
        
        if username and password:
            # Sanitizar inputs
            username = self.security.sanitize_input(username, 50)
            
            # Verificar rate limiting
            if not self._check_rate_limit(username):
                return
            
            # Obter IP para logging
            ip_address = st.session_state.get('client_ip', '127.0.0.1')
            
            logger.info(f"Login attempt for user: {username} from IP: {ip_address}")
            
            # Autenticar com IP para logging
            authenticated, has_mfa = self.db_manager.authenticate_user(
                username, password, ip_address
            )

            if authenticated:
                # Limpar tentativas após sucesso
                if username in st.session_state.login_attempts:
                    del st.session_state.login_attempts[username]
                
                if has_mfa:
                    st.session_state.awaiting_mfa = True
                    st.session_state.temp_username = username
                    st.session_state.remember_login = remember_me
                    st.success("✅ Digite o código MFA:")
                    st.rerun()
                else:
                    self.session_manager.complete_login(username, remember_me)
                    st.rerun()
            else:
                # Registrar tentativa falhada
                self._record_login_attempt(username)
                st.error("❌ Credenciais inválidas!")

    def _render_mfa_form(self):
        """Renderiza formulário MFA com proteção"""
        def cancel_mfa():
            st.session_state.awaiting_mfa = False
            st.session_state.temp_username = None
            if 'remember_login' in st.session_state:
                del st.session_state.remember_login
            st.rerun()

        # Validar que temos username temporário
        if 'temp_username' not in st.session_state:
            st.error("❌ Sessão expirada")
            cancel_mfa()
            return

        mfa_code = self.ui.show_mfa_form(
            st.session_state.temp_username,
            None,
            cancel_mfa
        )
        
        if mfa_code:
            # Sanitizar código MFA
            mfa_code = self.security.sanitize_input(mfa_code, 6)
            
            if self.mfa_manager.verify_mfa_token(st.session_state.temp_username, mfa_code):
                username = st.session_state.temp_username
                remember_me = st.session_state.get('remember_login', True)

                st.session_state.awaiting_mfa = False
                st.session_state.temp_username = None
                if 'remember_login' in st.session_state:
                    del st.session_state.remember_login

                self.session_manager.complete_login(username, remember_me)
                st.rerun()
            else:
                st.error("❌ Código MFA inválido!")

    def _render_footer(self):
        """Renderiza rodapé da página de login"""
        st.markdown("---")
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.caption(f"© 2024 {self.ui.config.COMPANY_NAME}")


class MFASetupPage:
    """Página para configurar MFA com validação de sessão"""
    
    def __init__(self, mfa_manager, ui_components):
        self.mfa_manager = mfa_manager
        self.ui = ui_components
        self.security = SecurityValidator()
    
    def render(self, username: str):
        """Renderiza a página de configuração MFA"""
        # Validar contexto do usuário
        if not self.security.validate_user_context(
            st.session_state.get('username'), username
        ):
            st.error("❌ Acesso não autorizado")
            return
        
        st.header("🔐 Configurar MFA")

        if not self.mfa_manager.is_available():
            st.error("❌ MFA indisponível - dependências não instaladas")
            st.info("Execute: pip install pyotp qrcode[pil] pillow")
            return

        try:
            mfa_secret, mfa_enabled = self.mfa_manager.get_user_mfa_info(username)

            if mfa_enabled:
                self._render_mfa_enabled(username)
            else:
                self._render_mfa_setup(username)

        except Exception as e:
            logger.error(f"MFA error for user {username}: {e}")
            st.error(f"Erro MFA: {e}")

    def _render_mfa_enabled(self, username: str):
        """Renderiza seção quando MFA está ativado"""
        st.success("✅ MFA ATIVADO")

        if st.button("🔴 Desativar MFA", type="secondary"):
            # Validar novamente antes de desativar
            if self.security.validate_user_context(
                st.session_state.get('username'), username
            ):
                self.mfa_manager.disable_mfa_for_user(username)
                st.success("MFA desativado!")
                st.rerun()

    def _render_mfa_setup(self, username: str):
        """Renderiza configuração inicial do MFA"""
        st.warning("⚠️ MFA DESATIVADO")

        if st.button("🔒 Configurar MFA"):
            secret = self.mfa_manager.setup_mfa_for_user(username)
            st.session_state.mfa_setup_secret = secret
            st.rerun()

        if 'mfa_setup_secret' in st.session_state:
            self._render_qr_code_setup(username)

    def _render_qr_code_setup(self, username: str):
        """Renderiza configuração do QR Code"""
        st.subheader("📱 Configure o Google Authenticator")

        qr_img = self.mfa_manager.generate_qr_code(
            username, 
            st.session_state.mfa_setup_secret
        )

        if qr_img:
            col1, col2 = st.columns([1, 1])

            with col1:
                st.image(qr_img, caption="Escaneie com Google Authenticator", width=300)

            with col2:
                st.write("**Passos:**")
                st.write("1. Instale o Google Authenticator")
                st.write("2. Escaneie o QR Code")
                st.write("3. Digite o código abaixo")

                st.write("**Código manual:**")
                st.code(st.session_state.mfa_setup_secret)

            self._render_verification_form(username)
        else:
            st.error("Erro ao gerar QR Code")
            st.code(st.session_state.mfa_setup_secret)

    def _render_verification_form(self, username: str):
        """Renderiza formulário de verificação MFA"""
        with st.form("verify_mfa"):
            verification_code = st.text_input("Código:", max_chars=6)

            col_verify, col_cancel = st.columns(2)
            with col_verify:
                verify_button = st.form_submit_button("✅ Ativar MFA", use_container_width=True)
            with col_cancel:
                cancel_button = st.form_submit_button("❌ Cancelar", type="secondary", use_container_width=True)

            if cancel_button:
                del st.session_state.mfa_setup_secret
                st.rerun()

            if verify_button:
                if len(verification_code) == 6 and verification_code.isdigit():
                    if self.mfa_manager.enable_mfa_for_user(username, verification_code):
                        del st.session_state.mfa_setup_secret
                        st.success("🎉 MFA ativado!")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error("Código inválido!")
                else:
                    st.error("Digite 6 dígitos!")


class TemporaryLinksPage:
    """Página para gerenciar links temporários com proteção IDOR"""
    
    def __init__(self, db_manager, ui_components):
        self.db_manager = db_manager
        self.ui = ui_components
        self.security = SecurityValidator()
    
    def render(self, username: str):
        """Renderiza a página de links temporários"""
        # Validar contexto do usuário
        if not self.security.validate_user_context(
            st.session_state.get('username'), username
        ):
            st.error("❌ Acesso não autorizado")
            return
        
        st.header("🔗 Links Temporários")

        tab1, tab2 = st.tabs(["📤 Criar Link", "📋 Meus Links"])

        with tab1:
            self._render_create_link_tab(username)

        with tab2:
            self._render_manage_links_tab(username)

    def _render_create_link_tab(self, username: str):
        """Renderiza aba de criação de links com validação IDOR"""
        # Obter apenas arquivos do usuário autenticado
        files = self.db_manager.get_user_files(username)

        if not files:
            st.warning("Faça upload de arquivos primeiro.")
            return

        file_options = {}
        
        # Processar arquivos com validação
        for file_data in files:
            try:
                # Suportar diferentes formatos de retorno
                if len(file_data) >= 5:
                    file_key = file_data[0]
                    original_name = file_data[1]
                    file_size = file_data[2]
                    
                    # Validar que o arquivo pertence ao usuário
                    if self.db_manager.validate_file_access(username, file_key, log_access=False):
                        display_name = f"{original_name} ({file_size:,} bytes)"
                        file_options[display_name] = file_key
                    else:
                        logger.warning(f"IDOR: User {username} tried to list file {file_key}")
            except Exception as e:
                logger.error(f"Error processing file data: {e}")
                continue

        if not file_options:
            st.warning("Nenhum arquivo válido encontrado.")
            return

        with st.form("create_temp_link"):
            selected_display = st.selectbox("Arquivo:", list(file_options.keys()))

            col1, col2 = st.columns(2)
            with col1:
                max_accesses = st.number_input(
                    "Máx acessos:", 
                    min_value=1, 
                    max_value=1000, 
                    value=3
                )
            with col2:
                expires_hours = st.number_input(
                    "Válido por (horas):", 
                    min_value=1, 
                    max_value=1440, 
                    value=48
                )
            
            # Opção de restrição por IP
            restrict_ip = st.checkbox("Restringir por IP")
            ip_restrictions = None
            
            if restrict_ip:
                ip_list = st.text_area(
                    "IPs permitidos (um por linha):",
                    help="Deixe vazio para permitir qualquer IP"
                )
                if ip_list:
                    ip_restrictions = [
                        ip.strip() for ip in ip_list.split('\n') 
                        if ip.strip()
                    ]

            if st.form_submit_button("🔗 Gerar Link"):
                try:
                    selected_file_key = file_options[selected_display]
                    
                    # Validar novamente antes de criar o link
                    if not self.db_manager.validate_file_access(username, selected_file_key):
                        st.error("❌ Acesso negado ao arquivo")
                        logger.error(f"IDOR: {username} tried to create link for {selected_file_key}")
                        return

                    link_token, access_token = self.db_manager.create_temporary_link(
                        file_key=selected_file_key,
                        username=username,
                        max_accesses=max_accesses,
                        expires_hours=expires_hours,
                        ip_restrictions=ip_restrictions
                    )

                    if link_token and access_token:
                        st.success("✅ Link criado com sucesso!")

                        temp_link = f"{self.ui.config.BASE_URL}/?temp_link={link_token}"

                        st.write("**🔗 Link:**")
                        st.code(temp_link)

                        st.write("**🔑 Token de Acesso:**")
                        st.code(access_token)

                        st.warning("⚠️ Compartilhe o link e o token separadamente para maior segurança!")
                        
                        if ip_restrictions:
                            st.info(f"🔒 Restrito aos IPs: {', '.join(ip_restrictions)}")
                    else:
                        st.error("❌ Erro ao criar link temporário")

                except Exception as e:
                    logger.error(f"Error creating temporary link: {e}")
                    st.error(f"Erro: {e}")

    def _render_manage_links_tab(self, username: str):
        """Renderiza aba de gerenciamento de links com proteção IDOR"""
        # Obter apenas links do usuário autenticado
        temp_links = self.db_manager.get_user_temporary_links(username)

        if not temp_links:
            st.info("Nenhum link temporário criado.")
            return

        for link_data in temp_links:
            try:
                # Desempacotar com segurança
                if len(link_data) >= 9:
                    (link_token, filename, access_token, max_acc, current_acc, 
                     expires_at, created_at, is_active, file_key) = link_data[:9]
                    
                    # Informações adicionais se disponíveis
                    link_uuid = link_data[9] if len(link_data) > 9 else None
                    last_accessed = link_data[10] if len(link_data) > 10 else None
                    
                    self._render_link_item(
                        link_token, filename, access_token, max_acc, current_acc,
                        expires_at, created_at, is_active, username, file_key,
                        link_uuid, last_accessed
                    )
            except Exception as e:
                logger.error(f"Error rendering link item: {e}")
                continue

    def _render_link_item(self, link_token: str, filename: str, access_token: str,
                         max_acc: int, current_acc: int, expires_at: datetime,
                         created_at: datetime, is_active: bool, username: str,
                         file_key: str, link_uuid: str = None, last_accessed: datetime = None):
        """Renderiza item individual de link temporário"""
        with st.container():
            now = datetime.now()
            is_expired = now > expires_at
            is_exhausted = current_acc >= max_acc

            # Determinar status
            if not is_active:
                status = "🔴 Desativado"
                status_color = "red"
            elif is_expired:
                status = "⏰ Expirado"
                status_color = "orange"
            elif is_exhausted:
                status = "📊 Esgotado"
                status_color = "yellow"
            else:
                status = "🟢 Ativo"
                status_color = "green"

            col1, col2, col3 = st.columns([3, 1, 1])

            with col1:
                st.write(f"**📄 {filename}**")
                st.write(f"Criado: {created_at.strftime('%d/%m/%Y %H:%M')}")
                st.write(f"Expira: {expires_at.strftime('%d/%m/%Y %H:%M')}")
                
                if last_accessed:
                    st.write(f"Último acesso: {last_accessed.strftime('%d/%m/%Y %H:%M')}")

            with col2:
                st.markdown(f"<span style='color: {status_color}'>{status}</span>", 
                           unsafe_allow_html=True)
                st.write(f"Acessos: {current_acc}/{max_acc}")

                if is_active and not is_expired and not is_exhausted:
                    # Gerar chave única para o botão
                    button_key = f"show_{link_token[:8]}_{hashlib.md5(link_token.encode()).hexdigest()[:8]}"
                    
                    if st.button("👁️ Ver Token", key=button_key, use_container_width=True):
                        st.code(access_token)
                        
                        # Mostrar link completo
                        temp_link = f"{self.ui.config.BASE_URL}/?temp_link={link_token}"
                        st.info(f"Link: {temp_link}")

            with col3:
                if is_active and not is_expired:
                    # Gerar chave única para o botão de desativar
                    deact_key = f"deact_{link_token[:8]}_{hashlib.md5(link_token.encode()).hexdigest()[:8]}"
                    
                    if st.button("🗑️ Desativar", key=deact_key, type="secondary", use_container_width=True):
                        # Validar que o usuário é o dono antes de desativar
                        if self.db_manager.deactivate_temporary_link(link_token, username):
                            st.success("✅ Link desativado!")
                            st.rerun()
                        else:
                            st.error("❌ Erro ao desativar link")

            st.divider()


class TemporaryLinkAccessPage:
    """Página para acessar link temporário (acesso público com token)"""
    
    def __init__(self, db_manager, s3_manager, ui_components):
        self.db_manager = db_manager
        self.s3_manager = s3_manager
        self.ui = ui_components
        self.security = SecurityValidator()
    
    def render(self, link_token: str):
        """Renderiza a página de acesso a link temporário"""
        self.ui.display_header_with_logo(
            "🔗 Acesso a Link Temporário", 
            f"Sistema seguro - {self.ui.config.COMPANY_NAME}"
        )

        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            # Mostrar apenas parte do token por segurança
            safe_token_display = f"{link_token[:8]}...{link_token[-4:]}"
            st.info(f"🔗 Link: `{safe_token_display}`")

            # Inicializar estado da sessão
            if 'temp_link_validated' not in st.session_state:
                st.session_state.temp_link_validated = False
            if 'temp_file_data' not in st.session_state:
                st.session_state.temp_file_data = None
            if 'temp_filename' not in st.session_state:
                st.session_state.temp_filename = None

            if not st.session_state.temp_link_validated:
                self._render_access_form(link_token)
            else:
                self._render_download_section()

    def _render_access_form(self, link_token: str):
        """Renderiza formulário de acesso com proteção"""
        with st.form("temp_access"):
            access_token = st.text_input(
                "🔑 Token de Acesso (6 dígitos):", 
                max_chars=6, 
                placeholder="123456",
                type="password"
            )

            if st.form_submit_button("🔓 Acessar Arquivo", use_container_width=True):
                if len(access_token) == 6 and access_token.isdigit():
                    # Obter IP do cliente
                    ip_address = st.session_state.get('client_ip', '127.0.0.1')
                    
                    # Validar link temporário
                    is_valid, file_key, message = self.db_manager.validate_temporary_link(
                        link_token, access_token, ip_address
                    )

                    if is_valid and file_key:
                        st.success(f"✅ {message}")

                        # Baixar arquivo do S3
                        with st.spinner("Preparando arquivo..."):
                            file_data = self.s3_manager.download_file(file_key)

                        if file_data:
                            # Obter nome do arquivo
                            conn = self.db_manager.get_connection()
                            cursor = conn.cursor()
                            cursor.execute(
                                "SELECT original_name, file_size FROM files WHERE file_key = %s",
                                (file_key,)
                            )
                            result = cursor.fetchone()
                            cursor.close()
                            conn.close()

                            if result:
                                filename, file_size = result
                            else:
                                filename = "arquivo"
                                file_size = len(file_data)

                            # Armazenar na sessão
                            st.session_state.temp_link_validated = True
                            st.session_state.temp_file_data = file_data
                            st.session_state.temp_filename = filename
                            st.session_state.temp_file_size = file_size

                            st.rerun()
                        else:
                            st.error("❌ Erro ao preparar download.")
                    else:
                        st.error(f"❌ {message}")
                        
                        # Log de tentativa falhada
                        logger.warning(f"Failed temp link access: {message}")
                else:
                    st.error("❌ Token deve ter 6 dígitos!")

    def _render_download_section(self):
        """Renderiza seção de download"""
        st.success("✅ Arquivo pronto para download!")

        # Informações do arquivo
        file_size = st.session_state.get('temp_file_size', len(st.session_state.temp_file_data))
        filename = st.session_state.temp_filename
        
        # Exibir informações
        st.write(f"📄 **Nome:** {filename}")
        st.write(f"📊 **Tamanho:** {file_size:,} bytes")
        
        # Calcular hash para verificação
        file_hash = hashlib.sha256(st.session_state.temp_file_data).hexdigest()[:16]
        st.write(f"🔐 **Verificação:** `{file_hash}`")

        # Botão de download
        st.download_button(
            "📥 Baixar Arquivo",
            data=st.session_state.temp_file_data,
            file_name=filename,
            use_container_width=True,
            type="primary"
        )

        # Opção de tentar outro token
        if st.button("🔄 Acessar Outro Arquivo", type="secondary", use_container_width=True):
            st.session_state.temp_link_validated = False
            st.session_state.temp_file_data = None
            st.session_state.temp_filename = None
            st.session_state.temp_file_size = None
            st.rerun()


class MainApplicationPage:
    """Página principal da aplicação com proteção IDOR completa"""
    
    def __init__(self, db_manager, s3_manager, session_manager, mfa_manager, ui_components):
        self.db_manager = db_manager
        self.s3_manager = s3_manager
        self.session_manager = session_manager
        self.mfa_manager = mfa_manager
        self.ui = ui_components
        self.temp_links_page = TemporaryLinksPage(db_manager, ui_components)
        self.mfa_setup_page = MFASetupPage(mfa_manager, ui_components)
        self.security = SecurityValidator()
    
    def render(self, username: str):
        """Renderiza a aplicação principal com validação de sessão"""
        # Validar que o usuário da sessão corresponde
        session_username = st.session_state.get('username')
        if not self.security.validate_user_context(session_username, username):
            st.error("❌ Sessão inválida. Por favor, faça login novamente.")
            self.session_manager.perform_logout()
            st.rerun()
            return
        
        self.ui.display_header_with_logo(
            f"Pluxee - {username}", 
            "Compartilhamento de Arquivos Pluxee"
        )

        self._render_sidebar(username)

        # Tabs principais
        tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload", "📥 Arquivos", "🔗 Links", "🔐 Segurança"])

        with tab1:
            self._render_upload_tab(username)

        with tab2:
            self._render_files_tab(username)

        with tab3:
            self.temp_links_page.render(username)

        with tab4:
            self.mfa_setup_page.render(username)

    def _render_sidebar(self, username: str):
        """Renderiza sidebar com informações do usuário"""
        with st.sidebar:
            self.ui.display_sidebar_logo()

            try:
                _, mfa_enabled = self.mfa_manager.get_user_mfa_info(username)
            except:
                mfa_enabled = None

            has_persistent_session = bool(st.session_state.get('session_token'))

            self.ui.display_user_info(username, mfa_enabled, has_persistent_session)

            st.sidebar.markdown("---")

            # Botão de logout
            if st.button("🚪 Logout", type="secondary", use_container_width=True):
                self.session_manager.perform_logout()
                st.rerun()

            # Informações de segurança
            st.sidebar.markdown("---")
            st.sidebar.caption("🔒 Conexão Segura")
            
            # Mostrar IP se disponível
            if 'client_ip' in st.session_state:
                st.sidebar.caption(f"📍 IP: {st.session_state.client_ip}")

            self.ui.display_footer()

    def _render_upload_tab(self, username: str):
        """Renderiza aba de upload com proteção e feedback aprimorado"""
        import time
        
        uploaded_file = self.ui.show_file_upload_section(None)
        
        if uploaded_file:
            # Validar arquivo antes do upload
            if not self._validate_upload(uploaded_file):
                return
            
            # Verificar tamanho do arquivo
            file_size_mb = uploaded_file.size / (1024 * 1024)
            is_large_file = file_size_mb > 100  # Arquivos > 100MB
            
            # Containers para status
            status_container = st.container()
            progress_container = st.container()
            
            try:
                with status_container:
                    if is_large_file:
                        st.warning(f"⏳ Arquivo grande detectado: {file_size_mb:.1f}MB")
                        st.info("📤 Iniciando upload... Não feche a página!")
                        
                        # Estimativa de tempo
                        estimated_seconds = file_size_mb / 10
                        if estimated_seconds > 60:
                            estimated_minutes = estimated_seconds / 60
                            st.info(f"⏱️ Tempo estimado: ~{estimated_minutes:.1f} minutos")
                        else:
                            st.info(f"⏱️ Tempo estimado: ~{estimated_seconds:.0f} segundos")
                    else:
                        st.info("📤 Fazendo upload...")
                
                # Progress bar para arquivos grandes
                progress_bar = None
                status_text = None
                
                if is_large_file:
                    with progress_container:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        progress_bar.progress(5)
                        status_text.text("📊 Preparando upload...")
                
                # Preparar upload com nome seguro
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                # Gerar file_key único e seguro
                file_hash = hashlib.sha256(
                    f"{username}{timestamp}{uploaded_file.name}".encode()
                ).hexdigest()[:8]
                
                file_key = f"{username}/{timestamp}_{file_hash}_{uploaded_file.name}"
                
                # Log de início
                logger.info(f"Starting upload: {uploaded_file.name} ({file_size_mb:.1f}MB) by {username}")
                
                # Reset file pointer
                uploaded_file.seek(0)
                
                # Atualizar progresso
                if is_large_file and progress_bar and status_text:
                    progress_bar.progress(15)
                    status_text.text("📤 Transferindo dados...")
                
                # Upload real
                upload_start = time.time()
                
                if self.s3_manager.upload_file(uploaded_file, file_key):
                    upload_duration = time.time() - upload_start
                    actual_speed = file_size_mb / upload_duration if upload_duration > 0 else 0
                    
                    # Finalizar progress bar
                    if is_large_file and progress_bar and status_text:
                        progress_bar.progress(100)
                        status_text.success(f"✅ Upload concluído! Velocidade: {actual_speed:.1f}MB/s")
                    
                    # Salvar metadados com proteção IDOR
                    metadata_saved = self.db_manager.save_file_metadata(
                        file_key=file_key,
                        original_name=uploaded_file.name,
                        file_size=uploaded_file.size,
                        username=username,
                        mime_type=uploaded_file.type or "application/octet-stream"
                    )
                    
                    if metadata_saved:
                        # Log de sucesso
                        logger.info(f"Upload completed: {uploaded_file.name} in {upload_duration:.1f}s")
                        
                        # Limpar containers
                        status_container.empty()
                        progress_container.empty()
                        
                        # Mostrar sucesso
                        st.success(f"✅ Upload concluído! ({file_size_mb:.1f}MB em {upload_duration:.1f}s)")
                        st.balloons()
                        
                        # Aguardar antes de rerun
                        time.sleep(1)
                        st.rerun()
                    else:
                        status_container.empty()
                        progress_container.empty()
                        st.error("❌ Erro ao salvar metadados do arquivo")
                else:
                    status_container.empty()
                    progress_container.empty()
                    st.error("❌ Erro no upload para o S3!")
                    
            except Exception as e:
                # Limpar containers em caso de erro
                if 'status_container' in locals():
                    status_container.empty()
                if 'progress_container' in locals():
                    progress_container.empty()
                
                logger.error(f"Upload error for {uploaded_file.name}: {e}")
                st.error(f"❌ Erro durante upload: {str(e)}")
                
                # Debug info
                with st.expander("🔍 Informações de Debug"):
                    st.write(f"- Arquivo: {uploaded_file.name}")
                    st.write(f"- Tamanho: {file_size_mb:.1f}MB")
                    st.write(f"- Tipo: {uploaded_file.type}")
                    st.write(f"- Erro: {str(e)}")

    def _validate_upload(self, uploaded_file) -> bool:
        """Valida arquivo antes do upload"""
        # Verificar tamanho máximo (5GB)
        max_size = 5 * 1024 * 1024 * 1024
        if uploaded_file.size > max_size:
            st.error(f"❌ Arquivo muito grande! Máximo: {max_size / (1024**3):.1f}GB")
            return False
        
        # Verificar extensão perigosa
        dangerous_exts = {
            'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js',
            'jar', 'msi', 'app', 'deb', 'rpm', 'dmg', 'pkg'
        }
        
        file_ext = uploaded_file.name.split('.')[-1].lower() if '.' in uploaded_file.name else ''
        if file_ext in dangerous_exts:
            st.error(f"❌ Extensão .{file_ext} não permitida por segurança")
            return False
        
        return True

    def _render_files_tab(self, username: str):
        """Renderiza aba de arquivos com proteção IDOR completa"""
        # Obter apenas arquivos do usuário autenticado
        files = self.db_manager.get_user_files(username)
        
        def handle_download(file_key: str, original_name: str, idx: int):
            """Handler de download com validação IDOR"""
            # Validar acesso antes de permitir download
            if not self.db_manager.validate_file_access(username, file_key):
                st.error("❌ Acesso negado ao arquivo")
                logger.error(f"IDOR attempt: {username} tried to download {file_key}")
                return
            
            with st.spinner("Preparando download..."):
                file_data = self.s3_manager.download_file(file_key)

                if file_data:
                    # Registrar download com informações completas
                    ip_address = st.session_state.get('client_ip', '127.0.0.1')
                    user_agent = st.session_state.get('user_agent', 'Unknown')
                    
                    self.db_manager.record_download(
                        username, file_key, ip_address, user_agent, 'direct'
                    )

                    # Criar botão de download
                    st.download_button(
                        "📥 Clique para Baixar",
                        data=file_data,
                        file_name=original_name,
                        key=f"dlbtn_{idx}_{hashlib.md5(file_key.encode()).hexdigest()[:8]}",
                        use_container_width=True
                    )
                    st.success("✅ Download preparado!")
                    
                    # Mostrar hash para verificação
                    file_hash = hashlib.sha256(file_data).hexdigest()[:16]
                    st.info(f"🔐 Verificação: `{file_hash}`")
                    
                    st.rerun()
                else:
                    st.error("❌ Erro ao baixar arquivo")

        def handle_delete(file_key: str, idx: int):
            """Handler de delete com validação IDOR"""
            # Validar propriedade antes de deletar
            if not self.db_manager.validate_file_access(username, file_key, 'delete'):
                st.error("❌ Você não tem permissão para deletar este arquivo")
                logger.error(f"IDOR attempt: {username} tried to delete {file_key}")
                return
            
            # Confirmar deleção
            confirm_key = f"confirm_delete_{file_key}"
            
            if confirm_key not in st.session_state:
                st.session_state[confirm_key] = False
            
            if not st.session_state[confirm_key]:
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("⚠️ Confirmar Deleção", 
                               key=f"conf_{idx}_{hashlib.md5(file_key.encode()).hexdigest()[:8]}",
                               type="secondary"):
                        st.session_state[confirm_key] = True
                        st.rerun()
                with col2:
                    if st.button("❌ Cancelar", 
                               key=f"cancel_{idx}_{hashlib.md5(file_key.encode()).hexdigest()[:8]}"):
                        if confirm_key in st.session_state:
                            del st.session_state[confirm_key]
                        st.rerun()
            else:
                with st.spinner("Deletando..."):
                    # Deletar do S3
                    s3_deleted = self.s3_manager.delete_file(file_key)
                    
                    # Deletar metadados (com validação IDOR interna)
                    db_deleted = self.db_manager.delete_file_metadata(file_key, username)

                    if db_deleted:
                        st.success("✅ Arquivo deletado com sucesso!")
                        if confirm_key in st.session_state:
                            del st.session_state[confirm_key]
                        logger.info(f"File deleted: {file_key} by {username}")
                        st.rerun()
                    else:
                        st.error("❌ Erro ao deletar arquivo")
                        if confirm_key in st.session_state:
                            del st.session_state[confirm_key]

        # Mostrar lista de arquivos
        self.ui.show_file_list(files, handle_download, handle_delete)

# Log de inicialização
logger.info("✅ Pages module with IDOR protection loaded successfully")
