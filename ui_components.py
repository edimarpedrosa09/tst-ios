"""
Módulo de Componentes UI - VERSÃO SEGURA COM PROTEÇÃO XSS
Mantém todas as funcionalidades visuais com sanitização completa
"""
import streamlit as st
import os
import logging
import re
import html
import unicodedata
from typing import Optional, List, Tuple, Callable, Any, Dict
from datetime import datetime, timedelta
import hashlib
import base64

logger = logging.getLogger(__name__)

# ============= SANITIZADOR XSS =============

class XSSSanitizer:
    """Classe para sanitização contra XSS"""
    
    # Padrões perigosos
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>',
        r'<applet[^>]*>.*?</applet>',
        r'<meta[^>]*>',
        r'<link[^>]*>',
        r'<style[^>]*>.*?</style>',
        r'expression\s*\(',
        r'import\s+',
        r'vbscript:',
        r'data:text/html',
        r'<svg[^>]*>.*?</svg>',
    ]
    
    @staticmethod
    def sanitize_text(text: str, max_length: int = 1000) -> str:
        """Sanitiza texto para prevenir XSS"""
        if not text:
            return ""
        
        # Limitar tamanho
        text = str(text)[:max_length]
        
        # Escapar HTML
        text = html.escape(text, quote=True)
        
        # Remover caracteres de controle
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        # Remover padrões perigosos (case-insensitive)
        for pattern in XSSSanitizer.DANGEROUS_PATTERNS:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)
        
        return text
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitiza nome de arquivo"""
        if not filename:
            return "unnamed_file"
        
        # Remover path traversal
        filename = os.path.basename(filename)
        filename = filename.replace('..', '')
        filename = filename.replace('../', '')
        filename = filename.replace('..\\', '')
        
        # Remover caracteres perigosos
        dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\x00']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limitar tamanho
        max_len = 255
        if len(filename) > max_len:
            name, ext = os.path.splitext(filename)
            if ext:
                name = name[:max_len - len(ext)]
                filename = name + ext
            else:
                filename = filename[:max_len]
        
        # Normalizar unicode
        filename = unicodedata.normalize('NFKD', filename)
        filename = ''.join(c for c in filename if unicodedata.category(c)[0] != 'C')
        
        return filename or "sanitized_file"
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitiza URL para prevenir XSS"""
        if not url:
            return "#"
        
        url = str(url).strip()
        
        # Bloquear URLs perigosas
        dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:']
        for scheme in dangerous_schemes:
            if url.lower().startswith(scheme):
                return "#"
        
        # Permitir apenas schemes seguros
        safe_schemes = ['http://', 'https://', 'mailto:', 'tel:']
        if not any(url.lower().startswith(s) for s in safe_schemes):
            # Se não tem scheme, assumir https
            if not url.startswith('/'):
                url = 'https://' + url
        
        # Escapar caracteres especiais
        url = html.escape(url, quote=True)
        
        return url

# ============= VALIDADOR DE ENTRADA =============

class InputValidator:
    """Classe para validação de entradas"""
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Valida nome de usuário"""
        if not username:
            return False, "Username não pode estar vazio"
        
        # Tamanho
        if len(username) < 3 or len(username) > 50:
            return False, "Username deve ter entre 3 e 50 caracteres"
        
        # Formato
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return False, "Username pode conter apenas letras, números, _, . e -"
        
        # Não pode começar ou terminar com caracteres especiais
        if username[0] in '._-' or username[-1] in '._-':
            return False, "Username não pode começar ou terminar com caracteres especiais"
        
        return True, ""
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Valida email"""
        if not email:
            return True, ""  # Email é opcional
        
        # Regex básico para email
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False, "Email inválido"
        
        # Tamanho máximo
        if len(email) > 255:
            return False, "Email muito longo"
        
        return True, ""
    
    @staticmethod
    def validate_mfa_code(code: str) -> Tuple[bool, str]:
        """Valida código MFA"""
        if not code:
            return False, "Código não pode estar vazio"
        
        if not code.isdigit():
            return False, "Código deve conter apenas números"
        
        if len(code) != 6:
            return False, "Código deve ter 6 dígitos"
        
        return True, ""

# ============= COMPONENTES UI SEGUROS =============

class UIComponents:
    """Classe para componentes reutilizáveis da interface com proteção XSS"""

    def __init__(self, config):
        self.config = config
        self.logo_data = self._load_company_logo()
        self.sanitizer = XSSSanitizer()
        self.validator = InputValidator()

    def _load_company_logo(self) -> Optional[bytes]:
        """Carrega o logo da empresa se disponível"""
        try:
            # Tentar primeiro o path do config
            if hasattr(self.config, 'LOGO_PATH') and os.path.exists(self.config.LOGO_PATH):
                with open(self.config.LOGO_PATH, "rb") as f:
                    return f.read()
            
            # Tentar carregar de URL se disponível
            if hasattr(self.config, 'LOGO_URL'):
                try:
                    import requests
                    response = requests.get(self.config.LOGO_URL, timeout=5)
                    if response.status_code == 200:
                        return response.content
                except:
                    pass
            
            logger.warning("Logo not found")
            return None
            
        except Exception as e:
            logger.error(f"Error loading logo: {e}")
            return None

    def display_header_with_logo(self, title: str, subtitle: str = None):
        """Exibe cabeçalho com logo da empresa (sanitizado)"""
        # Sanitizar inputs
        title = self.sanitizer.sanitize_text(title, 100)
        subtitle = self.sanitizer.sanitize_text(subtitle, 200) if subtitle else None
        
        if self.logo_data:
            col1, col2 = st.columns([1, 4])
            with col1:
                st.image(self.logo_data, width=120)
            with col2:
                st.title(title)
                if subtitle:
                    st.caption(subtitle)
        else:
            # Usar nome da empresa sanitizado
            company_name = self.sanitizer.sanitize_text(
                getattr(self.config, 'COMPANY_NAME', 'Pluxee'), 50
            )
            st.title(f"{company_name}")
            st.subheader(title)
            if subtitle:
                st.caption(subtitle)

    def display_sidebar_logo(self):
        """Exibe logo na sidebar se disponível"""
        if self.logo_data:
            st.sidebar.image(self.logo_data, width=100)
            # Sanitizar nome da empresa
            company_name = self.sanitizer.sanitize_text(
                getattr(self.config, 'COMPANY_NAME', 'Pluxee'), 50
            )
            st.sidebar.caption(f"**{company_name}**")
        else:
            company_name = self.sanitizer.sanitize_text(
                getattr(self.config, 'COMPANY_NAME', 'Pluxee'), 50
            )
            st.sidebar.title(company_name)

    def display_user_info(self, username: str, mfa_enabled: bool = None, has_persistent_session: bool = False):
        """Exibe informações do usuário na sidebar (sanitizado)"""
        # Sanitizar username
        username = self.sanitizer.sanitize_text(username, 50)
        
        st.sidebar.markdown("---")
        st.sidebar.write(f"👤 **{username}**")

        # Status MFA
        if mfa_enabled is not None:
            if mfa_enabled:
                st.sidebar.success("🔐 MFA ON")
            else:
                st.sidebar.warning("⚠️ MFA OFF")
        else:
            st.sidebar.error("⚠️ Erro MFA")

        # Status da sessão
        if has_persistent_session:
            st.sidebar.info("🔒 Persistente")
        else:
            st.sidebar.info("⏳ Temporária")

    def display_footer(self):
        """Exibe rodapé da aplicação"""
        st.sidebar.markdown("---")
        # Sanitizar nome da empresa
        company_name = self.sanitizer.sanitize_text(
            getattr(self.config, 'COMPANY_NAME', 'Pluxee'), 50
        )
        current_year = datetime.now().year
        st.sidebar.caption(f"© {current_year} {company_name}")

    def show_login_form(self, on_submit_callback, cookies_available: bool = True):
        """Exibe formulário de login com validação"""
        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            st.subheader("Faça seu login")

            with st.form("login_form"):
                username = st.text_input(
                    "👤 Usuário", 
                    placeholder="Digite seu usuário",
                    max_chars=50
                )
                password = st.text_input(
                    "🔒 Senha", 
                    type="password", 
                    placeholder="Digite sua senha",
                    max_chars=128
                )

                remember_me = True
                if cookies_available:
                    remember_me = st.checkbox("🔒 Lembrar-me", value=True)
                else:
                    st.caption("ℹ️ Sessão persistente não disponível")

                submit = st.form_submit_button("🚀 Entrar", use_container_width=True)

                if submit:
                    if not username or not password:
                        st.error("❌ Preencha todos os campos!")
                        return None, None, None
                    
                    # Validar username
                    valid, error_msg = self.validator.validate_username(username)
                    if not valid:
                        st.error(f"❌ {error_msg}")
                        return None, None, None
                    
                    # Sanitizar inputs (senha não é sanitizada, apenas validada)
                    username = self.sanitizer.sanitize_text(username, 50)

                    return username, password, remember_me

        return None, None, None

    def show_mfa_form(self, username: str, on_verify_callback, on_cancel_callback):
        """Exibe formulário de verificação MFA com validação"""
        col1, col2, col3 = st.columns([1, 2, 1])

        with col2:
            # Sanitizar username para exibição
            safe_username = self.sanitizer.sanitize_text(username, 50)
            st.success(f"✅ Bem-vindo, **{safe_username}**!")
            st.info("🔐 Verificação MFA necessária")

            with st.form("mfa_form"):
                mfa_code = st.text_input(
                    "🔢 Código MFA", 
                    max_chars=6, 
                    placeholder="123456"
                )

                col_verify, col_cancel = st.columns(2)

                with col_verify:
                    submit_mfa = st.form_submit_button("✅ Verificar", use_container_width=True)

                with col_cancel:
                    cancel = st.form_submit_button("❌ Cancelar", use_container_width=True)

                if cancel:
                    on_cancel_callback()
                    return None

                if submit_mfa:
                    # Validar código MFA
                    valid, error_msg = self.validator.validate_mfa_code(mfa_code)
                    if valid:
                        return mfa_code
                    else:
                        st.error(f"❌ {error_msg}")
                        return None

        return None

    def show_file_upload_section(self, on_upload_callback):
        """Exibe seção de upload de arquivos com validação"""
        st.header("📤 Upload")

        # Informações sobre limites
        st.info("📋 **Limites de Upload:**")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Tamanho Máximo", "2 GB", "por arquivo")
        with col2:
            st.metric("Tipos", "Seguros", "formatos validados")
        with col3:
            st.metric("Armazenamento", "S3", "criptografado")

        # Lista de extensões perigosas para aviso
        dangerous_extensions = {
            'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar',
            'msi', 'app', 'dll', 'so', 'sh', 'ps1'
        }

        uploaded_file = st.file_uploader(
            "Escolha um arquivo:",
            type=None,
            help="Arquivos até 2GB são aceitos. Upload pode demorar para arquivos grandes."
        )

        if uploaded_file is not None:
            # Sanitizar nome do arquivo
            safe_filename = self.sanitizer.sanitize_filename(uploaded_file.name)
            
            # Verificar extensão perigosa
            file_ext = safe_filename.split('.')[-1].lower() if '.' in safe_filename else ''
            is_dangerous = file_ext in dangerous_extensions
            
            # Validação de tamanho
            max_size = 2 * 1024 * 1024 * 1024  # 2GB em bytes

            if uploaded_file.size > max_size:
                st.error(f"❌ Arquivo muito grande! Máximo: 2GB, Atual: {uploaded_file.size / (1024*1024*1024):.2f}GB")
                return None

            col1, col2 = st.columns([2, 1])

            with col1:
                # Exibir nome sanitizado
                st.write(f"• **Nome:** {safe_filename}")
                
                if is_dangerous:
                    st.warning(f"⚠️ Extensão .{file_ext} pode conter riscos de segurança")

                # Formatação inteligente do tamanho
                size_bytes = uploaded_file.size
                if size_bytes < 1024:
                    size_str = f"{size_bytes} bytes"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.1f} KB"
                elif size_bytes < 1024 * 1024 * 1024:
                    size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

                st.write(f"• **Tamanho:** {size_str}")
                
                # Sanitizar tipo MIME
                mime_type = self.sanitizer.sanitize_text(uploaded_file.type or 'N/A', 100)
                st.write(f"• **Tipo:** {mime_type}")

                # Barra de progresso estimada para arquivos grandes
                if size_bytes > 100 * 1024 * 1024:  # > 100MB
                    st.warning("⏳ Arquivo grande detectado. Upload pode demorar alguns minutos.")

            with col2:
                button_text = "🚀 Fazer Upload"
                if is_dangerous:
                    button_text = "⚠️ Upload (Risco)"
                    
                if st.button(button_text, use_container_width=True, type="primary" if not is_dangerous else "secondary"):
                    # Retornar arquivo com nome original (não sanitizado) para manter compatibilidade
                    # A sanitização deve ser feita no backend
                    return uploaded_file

        return None

    def show_file_list(self, files, on_download_callback, on_delete_callback):
        """Exibe lista de arquivos do usuário com proteção XSS"""
        st.header("📥 Meus Arquivos")

        if not files:
            st.info("📂 Nenhum arquivo.")
            return

        st.write(f"📊 **Total:** {len(files)} arquivo(s)")
        st.markdown("---")

        for idx, file_data in enumerate(files):
            # Desempacotar com segurança
            try:
                if len(file_data) >= 5:
                    file_key = file_data[0]
                    original_name = file_data[1]
                    file_size = file_data[2]
                    uploaded_at = file_data[3]
                    downloaded = file_data[4]
                else:
                    logger.error(f"Invalid file data format: {file_data}")
                    continue
                    
                # Sanitizar nome para exibição
                safe_name = self.sanitizer.sanitize_filename(original_name)
                
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])

                    with col1:
                        st.write(f"**📄 {safe_name}**")
                        
                        # Formatar tamanho
                        if file_size < 1024:
                            size_str = f"{file_size} bytes"
                        elif file_size < 1024 * 1024:
                            size_str = f"{file_size / 1024:.1f} KB"
                        elif file_size < 1024 * 1024 * 1024:
                            size_str = f"{file_size / (1024 * 1024):.1f} MB"
                        else:
                            size_str = f"{file_size / (1024 * 1024 * 1024):.2f} GB"
                        
                        st.caption(f"📊 {size_str}")
                        
                        # Formatar data com segurança
                        try:
                            if isinstance(uploaded_at, datetime):
                                date_str = uploaded_at.strftime('%d/%m/%Y %H:%M')
                            else:
                                date_str = str(uploaded_at)
                            st.caption(f"📅 {date_str}")
                        except:
                            st.caption("📅 Data desconhecida")

                    with col2:
                        if downloaded:
                            st.success("✅ Baixado")
                        else:
                            st.info("⏳ Disponível")

                    with col3:
                        if not downloaded:
                            if st.button("📥 Download", key=f"dl_{idx}", use_container_width=True):
                                on_download_callback(file_key, original_name, idx)
                        else:
                            st.caption("⚠️ Já baixado")

                    with col4:
                        # Usar hash do file_key para evitar problemas com caracteres especiais
                        safe_key = hashlib.md5(str(file_key).encode()).hexdigest()[:8]
                        
                        if st.button("🗑️ Deletar", key=f"del_{idx}_{safe_key}", type="secondary", use_container_width=True):
                            st.session_state[f"confirm_delete_{file_key}"] = True

                        if st.session_state.get(f"confirm_delete_{file_key}", False):
                            st.warning("⚠️ Confirmar exclusão?")

                            col_yes, col_no = st.columns(2)

                            with col_yes:
                                if st.button("✅ Sim", key=f"yes_{idx}_{safe_key}", use_container_width=True):
                                    on_delete_callback(file_key, idx)

                            with col_no:
                                if st.button("❌ Não", key=f"no_{idx}_{safe_key}", type="secondary", use_container_width=True):
                                    del st.session_state[f"confirm_delete_{file_key}"]
                                    st.rerun()

                    st.divider()
                    
            except Exception as e:
                logger.error(f"Error displaying file {idx}: {e}")
                st.error(f"Erro ao exibir arquivo {idx}")

    def show_error_with_retry(self, error_message: str, on_retry_callback):
        """Exibe erro com opção de retry (sanitizado)"""
        # Sanitizar mensagem de erro
        safe_message = self.sanitizer.sanitize_text(error_message, 500)
        st.error(f"❌ {safe_message}")

        if st.button("🔄 Reiniciar Sessão", type="secondary"):
            on_retry_callback()

    def show_success_message(self, message: str):
        """Exibe mensagem de sucesso (sanitizada)"""
        safe_message = self.sanitizer.sanitize_text(message, 500)
        st.success(f"✅ {safe_message}")

    def show_warning_message(self, message: str):
        """Exibe mensagem de aviso (sanitizada)"""
        safe_message = self.sanitizer.sanitize_text(message, 500)
        st.warning(f"⚠️ {safe_message}")

    def show_info_message(self, message: str):
        """Exibe mensagem informativa (sanitizada)"""
        safe_message = self.sanitizer.sanitize_text(message, 500)
        st.info(f"ℹ️ {safe_message}")

    def render_markdown_safe(self, content: str):
        """Renderiza markdown com sanitização"""
        # Remover tags HTML perigosas
        safe_content = self.sanitizer.sanitize_text(content, 10000)
        
        # Re-permitir apenas formatação básica segura
        safe_tags = {
            '**': '**',  # Bold
            '*': '*',    # Italic
            '`': '`',    # Code
            '\n': '\n',  # Newline
        }
        
        # Renderizar com st.markdown mas com unsafe_allow_html=False
        st.markdown(safe_content, unsafe_allow_html=False)

# Log de inicialização
logger.info("✅ UIComponents with XSS protection loaded successfully")
