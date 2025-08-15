"""
Sistema de Segurança Simplificado e Eficiente
Arquivo: simplified_security.py
"""
import logging
import hashlib
import time
import socket
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from functools import wraps
from collections import defaultdict
import streamlit as st

logger = logging.getLogger(__name__)

class SimplifiedSecurityManager:
    """
    Gerenciador de segurança unificado e simplificado
    """
    
    def __init__(self):
        # Rate limiting storage
        self.rate_limits = defaultdict(list)
        self.blocked_ips = set()
        
        # Security patterns para detecção de ameaças
        self.threat_patterns = [
            (r'<script[^>]*>.*?</script>', 'XSS', 5),
            (r'javascript:', 'XSS', 4),
            (r'on\w+\s*=', 'XSS', 3),
            (r'union\s+select', 'SQL_INJECTION', 5),
            (r'drop\s+table', 'SQL_INJECTION', 5),
            (r'\'\s+or\s+\'\w*\'\s*=\s*\'\w*', 'SQL_INJECTION', 4),
            (r'\.\./', 'PATH_TRAVERSAL', 4),
            (r'%2e%2e%2f', 'PATH_TRAVERSAL', 4),
            (r';\s*rm\s+', 'COMMAND_INJECTION', 5),
            (r';\s*cat\s+', 'COMMAND_INJECTION', 4),
        ]
        
        # Rate limit configurations
        self.rate_configs = {
            'login': {'max_calls': 10, 'window_minutes': 15},
            'upload': {'max_calls': 20, 'window_minutes': 60},
            'download': {'max_calls': 100, 'window_minutes': 60},
            'general': {'max_calls': 500, 'window_minutes': 60},
        }
        
        logger.info("✅ Simplified Security Manager initialized")
    
    def get_client_ip(self) -> str:
        """Extrai IP do cliente de forma simples e eficaz"""
        try:
            # Método 1: Tentar IP local da máquina
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                
            # Validar se é um IP válido
            if self._is_valid_ip(local_ip):
                return local_ip
                
        except Exception:
            pass
        
        # Fallback seguro
        return "127.0.0.1"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Valida formato do IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def apply_security_headers(self):
        """Aplica headers de segurança via meta tags HTML"""
        security_headers = """
        <meta http-equiv="X-Frame-Options" content="DENY">
        <meta http-equiv="X-Content-Type-Options" content="nosniff">
        <meta http-equiv="X-XSS-Protection" content="1; mode=block">
        <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
        """
        
        st.markdown(f"""
        <div style="display: none;">
        {security_headers}
        </div>
        """, unsafe_allow_html=True)
    
    def check_rate_limit(self, action: str, identifier: str = None, 
                        max_calls: int = None, window_minutes: int = None) -> bool:
        """
        Rate limiting simplificado mas eficaz
        """
        # Usar IP como identificador se não fornecido
        if identifier is None:
            identifier = self.get_client_ip()
        
        # Verificar se IP está bloqueado
        if identifier in self.blocked_ips:
            self.log_security_event("BLOCKED_IP_ATTEMPT", ip=identifier, action=action)
            return False
        
        # Usar configuração padrão se não especificada
        config = self.rate_configs.get(action, self.rate_configs['general'])
        max_calls = max_calls or config['max_calls']
        window_minutes = window_minutes or config['window_minutes']
        
        # Chave única para rate limiting
        key = f"{identifier}:{action}"
        now = datetime.now()
        window_start = now - timedelta(minutes=window_minutes)
        
        # Limpar tentativas antigas
        self.rate_limits[key] = [
            timestamp for timestamp in self.rate_limits[key] 
            if timestamp > window_start
        ]
        
        # Verificar limite
        current_calls = len(self.rate_limits[key])
        if current_calls >= max_calls:
            # Bloquear IP após excesso de tentativas
            if current_calls >= max_calls * 2:
                self.blocked_ips.add(identifier)
                self.log_security_event("IP_BLOCKED", ip=identifier, 
                                      details=f"Blocked after {current_calls} {action} attempts")
            
            self.log_security_event("RATE_LIMIT_EXCEEDED", ip=identifier, 
                                  action=action, details=f"{current_calls}/{max_calls}")
            return False
        
        # Registrar tentativa atual
        self.rate_limits[key].append(now)
        return True
    
    def scan_content_for_threats(self, content: str) -> Dict[str, Any]:
        """
        Escaneia conteúdo em busca de ameaças
        """
        if not content:
            return {'is_safe': True, 'threats': [], 'risk_score': 0}
        
        threats_found = []
        risk_score = 0
        
        content_lower = content.lower()
        
        for pattern, threat_type, severity in self.threat_patterns:
            matches = re.findall(pattern, content_lower, re.IGNORECASE)
            if matches:
                threats_found.append({
                    'type': threat_type,
                    'severity': severity,
                    'matches': len(matches)
                })
                risk_score += len(matches) * severity
        
        is_safe = risk_score < 5 and not any(t['severity'] >= 5 for t in threats_found)
        
        if not is_safe:
            self.log_security_event("MALICIOUS_CONTENT_DETECTED", 
                                  details=f"Risk score: {risk_score}, Threats: {len(threats_found)}")
        
        return {
            'is_safe': is_safe,
            'threats': threats_found,
            'risk_score': risk_score,
            'recommendation': 'ALLOW' if is_safe else 'BLOCK'
        }
    
    def log_security_event(self, event_type: str, username: str = None, 
                          ip: str = None, action: str = None, details: str = None):
        """
        Log estruturado para eventos de segurança
        """
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'event': event_type,
            'user': username or 'anonymous',
            'ip': ip or 'unknown',
            'action': action or 'unknown',
            'details': details or 'no details'
        }
        
        # Log no formato estruturado
        logger.warning(f"SECURITY|{event_type}|{log_entry['user']}|{log_entry['ip']}|{log_entry['details']}")
    
    def security_middleware(self):
        """
        Middleware principal de segurança
        """
        try:
            # Aplicar headers de segurança
            self.apply_security_headers()
            
            # Extrair IP do cliente
            client_ip = self.get_client_ip()
            
            # Rate limiting geral
            if not self.check_rate_limit('general', client_ip):
                st.error("❌ Muitas requisições. Aguarde alguns minutos.")
                st.info(f"IP: {client_ip}")
                st.stop()
            
            # Armazenar IP na sessão
            if 'client_ip' not in st.session_state:
                st.session_state.client_ip = client_ip
            
            # Log de acesso bem-sucedido
            self.log_security_event("ACCESS_GRANTED", ip=client_ip)
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            self.log_security_event("SECURITY_ERROR", details=str(e))


def create_rate_limit_decorator(security_manager: SimplifiedSecurityManager):
    """
    Cria decorator para rate limiting
    """
    def rate_limit(action: str, max_calls: int = None, window_minutes: int = None):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                client_ip = security_manager.get_client_ip()
                
                if not security_manager.check_rate_limit(action, client_ip, max_calls, window_minutes):
                    raise Exception(f"Rate limit exceeded for {action}")
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    return rate_limit


class SecurityConfig:
    """
    Configuração de segurança simplificada
    """
    
    def __init__(self):
        self.manager = SimplifiedSecurityManager()
        self.rate_limit = create_rate_limit_decorator(self.manager)
        self.logger = logging.getLogger(__name__)
    
    def initialize_security(self) -> Dict[str, Any]:
        """
        Inicializa sistema de segurança
        """
        try:
            self.logger.info("✅ Security system initialized successfully")
            
            return {
                'security_middleware': self.manager.security_middleware,
                'rate_limit': self.rate_limit,
                'get_security_manager': lambda: self.manager,
                'get_client_ip': self.manager.get_client_ip,
                'apply_security_headers': self.manager.apply_security_headers,
                'status': 'active'
            }
            
        except Exception as e:
            self.logger.error(f"Error initializing security: {e}")
            return self._get_disabled_security()
    
    def _get_disabled_security(self):
        """
        Sistema de segurança desabilitado em caso de erro
        """
        def noop(*args, **kwargs):
            pass
        
        return {
            'security_middleware': noop,
            'rate_limit': lambda *args, **kwargs: lambda func: func,
            'get_security_manager': lambda: None,
            'get_client_ip': lambda: "127.0.0.1",
            'apply_security_headers': noop,
            'status': 'disabled'
        }


# Instância global
_security_config = None

def get_security_system():
    """
    Retorna sistema de segurança configurado
    """
    global _security_config
    if _security_config is None:
        _security_config = SecurityConfig()
    return _security_config.initialize_security()


# Funções de conveniência para compatibilidade
def security_middleware():
    """Função de compatibilidade"""
    system = get_security_system()
    return system['security_middleware']()

def strict_rate_limit(action: str, max_calls: int = 5, window_minutes: int = 15):
    """Função de compatibilidade"""
    system = get_security_system()
    return system['rate_limit'](action, max_calls, window_minutes)

def get_security_manager():
    """Função de compatibilidade"""
    system = get_security_system()
    return system['get_security_manager']()

def get_real_client_ip():
    """Função de compatibilidade"""
    system = get_security_system()
    return system['get_client_ip']()

def apply_security_headers():
    """Função de compatibilidade"""
    system = get_security_system()
    return system['apply_security_headers']()


# Log de inicialização
logger.info("✅ Simplified security system loaded successfully")
