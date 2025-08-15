"""
Módulo para gerenciamento de sessões e cookies
"""
import streamlit as st
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Verificação de dependências de cookies
try:
    import extra_streamlit_components as stx
    COOKIES_AVAILABLE = True
except ImportError:
    COOKIES_AVAILABLE = False
    logger.warning("Cookies functionality not available - extra_streamlit_components not installed")


class SessionManager:
    """Gerenciador de sessões de usuário"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.cookie_manager = self._init_cookie_manager()
    
    @staticmethod
    def is_cookies_available() -> bool:
        """Verifica se o gerenciamento de cookies está disponível"""
        return COOKIES_AVAILABLE
    
    def _init_cookie_manager(self):
        """Inicializa o gerenciador de cookies"""
        if COOKIES_AVAILABLE:
            try:
                return stx.CookieManager()
            except Exception as e:
                logger.error(f"Error initializing cookie manager: {e}")
                return None
        return None
    
    def init_session_state(self):
        """Inicializa estado da sessão"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'username' not in st.session_state:
            st.session_state.username = None
        if 'awaiting_mfa' not in st.session_state:
            st.session_state.awaiting_mfa = False
        if 'temp_username' not in st.session_state:
            st.session_state.temp_username = None
        if 'session_token' not in st.session_state:
            st.session_state.session_token = None
    
    def save_session_cookie(self, session_token: str):
        """Salva token de sessão no cookie"""
        if self.cookie_manager and session_token:
            try:
                self.cookie_manager.set(
                    'session_token', 
                    session_token, 
                    expires_at=datetime.now() + timedelta(days=1)
                )
                logger.info("Session token saved to cookie")
            except Exception as e:
                logger.error(f"Error saving session cookie: {e}")
    
    def get_session_cookie(self) -> Optional[str]:
        """Recupera token de sessão do cookie"""
        if self.cookie_manager:
            try:
                session_token = self.cookie_manager.get('session_token')
                if session_token:
                    logger.info("Session token retrieved from cookie")
                    return session_token
            except Exception as e:
                logger.error(f"Error getting session cookie: {e}")
        return None
    
    def clear_session_cookie(self):
        """Remove token de sessão do cookie"""
        if self.cookie_manager:
            try:
                self.cookie_manager.delete('session_token')
                logger.info("Session cookie cleared")
            except Exception as e:
                logger.error(f"Error clearing session cookie: {e}")
    
    def check_persistent_session(self) -> bool:
        """Verifica se há uma sessão persistente válida"""
        try:
            if st.session_state.authenticated:
                return True

            session_token = self.get_session_cookie()
            if not session_token:
                return False

            username = self.db_manager.validate_session_token(session_token)
            if username:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.session_token = session_token
                logger.info(f"Session restored for user: {username}")
                return True
            else:
                self.clear_session_cookie()
                return False

        except Exception as e:
            logger.error(f"Error checking persistent session: {e}")
            return False
    
    def complete_login(self, username: str, remember_me: bool = True):
        """Completa o processo de login"""
        try:
            st.session_state.authenticated = True
            st.session_state.username = username

            if remember_me and self.cookie_manager:
                session_token = self.db_manager.create_session_token(username)
                if session_token:
                    st.session_state.session_token = session_token
                    self.save_session_cookie(session_token)

            logger.info(f"User {username} logged in successfully")
            st.success("Login realizado com sucesso!")

        except Exception as e:
            logger.error(f"Error completing login: {e}")
            st.error("Erro ao finalizar login.")
    
    def perform_logout(self):
        """Realiza logout completo"""
        try:
            username = st.session_state.get('username', 'unknown')
            session_token = st.session_state.get('session_token')

            if session_token:
                self.db_manager.invalidate_session_token(session_token)

            self.clear_session_cookie()

            # Limpa todo o estado da sessão
            for key in list(st.session_state.keys()):
                del st.session_state[key]

            logger.info(f"User {username} logged out completely")

        except Exception as e:
            logger.error(f"Error during logout: {e}")
            # Força limpeza do estado mesmo com erro
            for key in list(st.session_state.keys()):
                del st.session_state[key]
    
    def cleanup_expired_sessions(self):
        """Limpa sessões expiradas do banco"""
        try:
            self.db_manager.cleanup_expired_sessions()
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
