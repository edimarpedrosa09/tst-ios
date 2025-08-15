"""
Configuração do sistema com módulos de segurança e upload
Versão que usa security_patches.py e upload_monitor.py
COM PROTEÇÃO CONTRA PATH TRAVERSAL
"""
import os
import logging
from typing import Dict, List, Set

# Configuração de logging
def setup_logging():
    """Configura o sistema de logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/app/logs/app.log') if os.path.exists('/app/logs') else logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# ============= CONFIGURAÇÕES DE SEGURANÇA PARA ARQUIVOS =============
class FileSecurityConfig:
    """Configurações de segurança para upload e manipulação de arquivos"""
    
    # Tamanhos máximos
    MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024  # 5GB
    MAX_FILENAME_LENGTH = 255
    MAX_FILES_PER_USER = 1000
    MAX_UPLOAD_BATCH_SIZE = 10  # Máximo de arquivos por vez
    
    # Extensões permitidas (whitelist)
    ALLOWED_EXTENSIONS: Set[str] = {
        # Documentos
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
        'odt', 'ods', 'odp', 'txt', 'rtf', 'csv',
        
        # Imagens
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico',
        
        # Vídeos
        'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm',
        
        # Áudio
        'mp3', 'wav', 'flac', 'aac', 'ogg', 'wma', 'm4a',
        
        # Arquivos compactados
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
        
        # Código (somente leitura)
        'py', 'js', 'html', 'css', 'json', 'xml', 'yaml', 'yml',
        'md', 'sql', 'ini', 'cfg', 'conf'
    }
    
    # Extensões bloqueadas (blacklist) - NUNCA permitir
    BLOCKED_EXTENSIONS: Set[str] = {
        'exe', 'dll', 'so', 'dylib', 'app', 'deb', 'rpm', 'dmg',
        'msi', 'com', 'cmd', 'bat', 'ps1', 'vbs', 'jar', 'scr',
        'lnk', 'inf', 'reg', 'gadget', 'application', 'msc',
        'vb', 'vbe', 'jse', 'ws', 'wsf', 'wsc', 'wsh', 'psc1',
        'cpl', 'msp', 'scf', 'hta', 'cab', 'hlp', 'msu', 'job',
        'rem', 'air', 'appx', 'appxbundle', 'deskthemepack'
    }
    
    # MIME types permitidos
    ALLOWED_MIME_TYPES: Set[str] = {
        # Imagens
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 
        'image/svg+xml', 'image/bmp', 'image/x-icon',
        
        # Documentos
        'application/pdf',
        'application/msword',
        'application/vnd.ms-excel',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.oasis.opendocument.text',
        'application/vnd.oasis.opendocument.spreadsheet',
        'application/vnd.oasis.opendocument.presentation',
        
        # Texto
        'text/plain', 'text/html', 'text/css', 'text/javascript',
        'text/csv', 'text/xml', 'text/markdown',
        
        # Aplicação
        'application/json', 'application/xml', 'application/yaml',
        'application/zip', 'application/x-rar-compressed',
        'application/x-7z-compressed', 'application/x-tar',
        'application/gzip', 'application/x-bzip2',
        
        # Vídeo
        'video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo',
        'video/x-ms-wmv', 'video/x-flv', 'video/webm',
        
        # Áudio
        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4',
        'audio/aac', 'audio/flac'
    }
    
    # Caracteres perigosos para Path Traversal
    DANGEROUS_PATH_CHARS = [
        '..', '../', '..\\',  # Path traversal
        '\x00',  # Null byte
        '%00',  # URL encoded null
        '%2e%2e',  # URL encoded ..
        '..;',  # Path traversal variant
        '..%2f',  # Mixed encoding
        '..%5c',  # Mixed encoding backslash
    ]
    
    # Nomes de arquivo reservados (Windows)
    RESERVED_FILENAMES = [
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
        'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
        'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
        'CLOCK$', 'CONFIG$'
    ]
    
    @classmethod
    def is_extension_allowed(cls, filename: str) -> bool:
        """Verifica se a extensão do arquivo é permitida"""
        if not filename:
            return False
            
        # Extrair extensão
        ext = os.path.splitext(filename.lower())[1].lstrip('.')
        
        # Verificar blacklist primeiro (prioridade)
        if ext in cls.BLOCKED_EXTENSIONS:
            return False
            
        # Verificar whitelist
        return ext in cls.ALLOWED_EXTENSIONS
    
    @classmethod
    def is_mime_type_allowed(cls, mime_type: str) -> bool:
        """Verifica se o MIME type é permitido"""
        if not mime_type:
            return False
        
        # Normalizar MIME type
        mime_type = mime_type.lower().split(';')[0].strip()
        
        return mime_type in cls.ALLOWED_MIME_TYPES
    
    @classmethod
    def has_path_traversal(cls, path: str) -> bool:
        """Detecta tentativas de path traversal"""
        if not path:
            return False
            
        # Verificar cada padrão perigoso
        for pattern in cls.DANGEROUS_PATH_CHARS:
            if pattern in path:
                return True
                
        # Verificar paths absolutos
        if path.startswith('/') or path.startswith('\\'):
            return True
            
        # Verificar drive letters (Windows)
        if len(path) > 1 and path[1] == ':':
            return True
            
        return False
    
    @classmethod
    def is_reserved_filename(cls, filename: str) -> bool:
        """Verifica se é um nome de arquivo reservado do sistema"""
        if not filename:
            return False
            
        # Extrair apenas o nome base sem extensão
        base_name = os.path.splitext(filename)[0].upper()
        
        return base_name in cls.RESERVED_FILENAMES

# Configurações globais (mantendo a classe original e adicionando segurança)
class Config:
    """Classe para centralizar todas as configurações"""

    # Paths e assets
    LOGO_PATH = "/app/assets/logo.png"
    COMPANY_NAME = os.getenv("COMPANY_NAME", "Sua Empresa")

    # Configurações do banco de dados
    DATABASE_URL = os.getenv("DATABASE_URL")

    # Configurações AWS
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.getenv("AWS_REGION")
    S3_BUCKET = os.getenv("S3_BUCKET")

    # URLs da aplicação
    BASE_URL = os.getenv("BASE_URL", "https://files-share.itpreprodb.com")

    # Configurações de segurança
    SECURITY_ENABLED = os.getenv("SECURITY_ENABLED", "true").lower() == "true"

    # Rate limiting
    DEFAULT_RATE_LIMIT = int(os.getenv("DEFAULT_RATE_LIMIT", "100"))

    # Configurações de bloqueio
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))
    BLOCK_DURATION_MINUTES = int(os.getenv("BLOCK_DURATION_MINUTES", "15"))
    
    # ===== ADICIONAR CONFIGURAÇÕES DE SEGURANÇA DE ARQUIVOS =====
    # Importar configurações de arquivo
    FILE_SECURITY = FileSecurityConfig
    
    # Configurações de upload
    MAX_FILE_SIZE = FileSecurityConfig.MAX_FILE_SIZE
    MAX_FILENAME_LENGTH = FileSecurityConfig.MAX_FILENAME_LENGTH
    ALLOWED_EXTENSIONS = FileSecurityConfig.ALLOWED_EXTENSIONS
    BLOCKED_EXTENSIONS = FileSecurityConfig.BLOCKED_EXTENSIONS
    
    # Configurações de sanitização
    SANITIZE_FILENAMES = os.getenv("SANITIZE_FILENAMES", "true").lower() == "true"
    SCAN_FOR_THREATS = os.getenv("SCAN_FOR_THREATS", "true").lower() == "true"
    ENFORCE_FILE_LIMITS = os.getenv("ENFORCE_FILE_LIMITS", "true").lower() == "true"

    @classmethod
    def get_required_env_vars(cls) -> Dict[str, str]:
        """Retorna dicionário com variáveis de ambiente obrigatórias"""
        return {
            "DATABASE_URL": cls.DATABASE_URL,
            "AWS_ACCESS_KEY_ID": cls.AWS_ACCESS_KEY_ID,
            "AWS_SECRET_ACCESS_KEY": cls.AWS_SECRET_ACCESS_KEY,
            "AWS_REGION": cls.AWS_REGION,
            "S3_BUCKET": cls.S3_BUCKET
        }

    @classmethod
    def validate_environment(cls) -> bool:
        """Valida se todas as variáveis de ambiente estão configuradas"""
        import streamlit as st

        logger = setup_logging()
        required_vars = cls.get_required_env_vars()
        missing_vars = [var for var, value in required_vars.items() if not value]

        if missing_vars:
            error_msg = f"Missing environment variables: {', '.join(missing_vars)}"
            logger.error(error_msg)
            st.error(f"❌ Variáveis de ambiente não configuradas: {', '.join(missing_vars)}")
            st.error("Configure todas as variáveis necessárias nos secrets do Kubernetes.")
            st.stop()

        logger.info("All environment variables validated successfully")
        return True

# Verificação de dependências
def check_dependencies():
    """Verifica se as dependências opcionais estão disponíveis"""
    logger = setup_logging()

    # Verificação MFA
    try:
        import pyotp
        import qrcode
        from PIL import Image
        MFA_AVAILABLE = True
        logger.info("✅ MFA dependencies available")
    except ImportError:
        MFA_AVAILABLE = False
        logger.debug("MFA dependencies not available")

    # Verificação Cookies
    try:
        import extra_streamlit_components as stx
        COOKIES_AVAILABLE = True
        logger.info("✅ Cookies dependencies available")
    except ImportError:
        COOKIES_AVAILABLE = False
        logger.debug("Cookies dependencies not available")

    # Verificação Security Patches - SEM WARNING
    try:
        import security_patches
        SECURITY_PATCHES_AVAILABLE = True
        logger.info("✅ Security patches available")
    except ImportError:
        SECURITY_PATCHES_AVAILABLE = False
        logger.debug("Security patches not found - will use integrated security")

    # Verificação Upload Monitor - SEM WARNING
    try:
        import upload_monitor
        UPLOAD_MONITOR_AVAILABLE = True
        logger.info("✅ Upload monitor available")
    except ImportError:
        UPLOAD_MONITOR_AVAILABLE = False
        logger.debug("Upload monitor not found - will use basic upload")

    return {
        'MFA_AVAILABLE': MFA_AVAILABLE,
        'COOKIES_AVAILABLE': COOKIES_AVAILABLE,
        'SECURITY_PATCHES_AVAILABLE': SECURITY_PATCHES_AVAILABLE,
        'UPLOAD_MONITOR_AVAILABLE': UPLOAD_MONITOR_AVAILABLE,
    }

# Sistema de segurança integrado
def setup_app_security():
    """
    Sistema de segurança com suporte a security_patches.py
    """
    # Validar ambiente primeiro
    Config.validate_environment()

    # Verificar dependências
    deps = check_dependencies()
    logger = setup_logging()

    # Log das dependências disponíveis
    if deps['MFA_AVAILABLE']:
        logger.info("✅ MFA system ready")

    if deps['COOKIES_AVAILABLE']:
        logger.info("✅ Persistent sessions ready")

    # Sistema de segurança
    if Config.SECURITY_ENABLED:
        if deps['SECURITY_PATCHES_AVAILABLE']:
            # Usar security_patches.py se disponível
            try:
                from security_patches import get_security_system
                security = get_security_system()
                logger.info(f"🛡️ Security patches loaded: {security['status']}")
                return {
                    'security': security,
                    'dependencies': deps,
                    'status': 'enhanced'
                }
            except Exception as e:
                logger.error(f"Error loading security_patches: {e}")
                # Fallback para sistema integrado
                pass

        # Sistema integrado como fallback
        logger.info("🛡️ Using integrated security system")
        return {
            'security': _get_integrated_security(),
            'dependencies': deps,
            'status': 'integrated'
        }
    else:
        logger.info("🔓 Security system disabled")
        return {
            'security': _get_disabled_security(),
            'dependencies': deps,
            'status': 'disabled'
        }

def _get_integrated_security():
    """Sistema de segurança integrado no config.py"""

    def security_middleware():
        """Middleware de segurança integrado"""
        import streamlit as st

        # Headers de segurança
        st.markdown("""
        <meta http-equiv="X-Frame-Options" content="DENY">
        <meta http-equiv="X-Content-Type-Options" content="nosniff">
        <meta http-equiv="X-XSS-Protection" content="1; mode=block">
        <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
        """, unsafe_allow_html=True)

    def rate_limit(action: str, max_calls: int = None, window_minutes: int = None):
        """Rate limiting integrado"""
        def decorator(func):
            import time
            from datetime import datetime, timedelta

            def wrapper(*args, **kwargs):
                # Rate limiting em memória
                if not hasattr(wrapper, '_calls'):
                    wrapper._calls = []

                now = datetime.now()
                window_start = now - timedelta(minutes=window_minutes or 60)

                # Limpar calls antigas
                wrapper._calls = [call_time for call_time in wrapper._calls if call_time > window_start]

                # Verificar limite
                max_allowed = max_calls or Config.DEFAULT_RATE_LIMIT
                if len(wrapper._calls) >= max_allowed:
                    raise Exception(f"Rate limit exceeded for {action}")

                # Registrar call
                wrapper._calls.append(now)

                return func(*args, **kwargs)
            return wrapper
        return decorator

    def get_client_ip():
        """Extração de IP integrada"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def sanitize_filename(filename: str) -> str:
        """Sanitiza nome de arquivo para prevenir Path Traversal"""
        import unicodedata
        import re
        
        if not filename:
            return "unnamed_file"
        
        # Remover path traversal
        filename = filename.replace('..', '')
        filename = filename.replace('../', '')
        filename = filename.replace('..\\', '')
        
        # Pegar apenas o nome base
        filename = os.path.basename(filename)
        
        # Normalizar Unicode
        filename = unicodedata.normalize('NFKD', filename)
        filename = ''.join(c for c in filename if unicodedata.category(c)[0] != 'C')
        
        # Remover caracteres perigosos
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        
        # Limitar tamanho
        if len(filename) > Config.MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(filename)
            max_name = Config.MAX_FILENAME_LENGTH - len(ext)
            filename = name[:max_name] + ext
        
        # Verificar extensão
        if not Config.FILE_SECURITY.is_extension_allowed(filename):
            filename = filename + '.txt'  # Adicionar .txt para neutralizar
        
        return filename or "sanitized_file"

    class IntegratedSecurityManager:
        """Manager de segurança integrado com proteção Path Traversal"""
        def __init__(self):
            self.logger = setup_logging()
            self.rate_limits = {}
            self.blocked_ips = set()
            self.file_security = FileSecurityConfig()

        def log_security_event(self, event_type: str, username: str = None,
                             ip: str = None, details: str = None):
            """Log estruturado de eventos de segurança"""
            self.logger.info(f"SECURITY|{event_type}|{username or 'anonymous'}|{ip or 'unknown'}|{details or 'no details'}")

        def check_rate_limit(self, action: str, identifier: str = None,
                           max_calls: int = None, window_minutes: int = None) -> bool:
            """Rate limiting com bloqueio de IP"""
            from datetime import datetime, timedelta

            identifier = identifier or get_client_ip()

            # Verificar se IP está bloqueado
            if identifier in self.blocked_ips:
                return False

            # Configurar limites
            max_calls = max_calls or Config.DEFAULT_RATE_LIMIT
            window_minutes = window_minutes or 60

            # Rate limiting
            key = f"{identifier}:{action}"
            now = datetime.now()
            window_start = now - timedelta(minutes=window_minutes)

            if key not in self.rate_limits:
                self.rate_limits[key] = []

            # Limpar calls antigas
            self.rate_limits[key] = [
                call_time for call_time in self.rate_limits[key]
                if call_time > window_start
            ]

            # Verificar limite
            if len(self.rate_limits[key]) >= max_calls:
                # Bloquear IP se exceder muito o limite
                if len(self.rate_limits[key]) >= max_calls * 2:
                    self.blocked_ips.add(identifier)
                    self.log_security_event("IP_BLOCKED", ip=identifier)

                return False

            # Registrar call
            self.rate_limits[key].append(now)
            return True

        def scan_content_for_threats(self, content: str) -> Dict:
            """Detecção básica de ameaças incluindo Path Traversal"""
            if not content:
                return {'is_safe': True, 'threats': [], 'risk_score': 0}

            # Padrões perigosos (incluindo path traversal)
            dangerous_patterns = [
                '<script', 'javascript:', 'onload=', 'onerror=', 'onclick=',
                'eval(', 'document.cookie', 'window.location',
                'union select', 'drop table', '; delete', '; update',
                '../', '..\\', '%2e%2e', 'cmd.exe', '/bin/sh',
                '..;', '..%2f', '..%5c',  # Path traversal variants
                '\x00', '%00',  # Null bytes
                'etc/passwd', 'windows/system32'  # System paths
            ]

            threats = []
            risk_score = 0
            content_lower = content.lower()

            for pattern in dangerous_patterns:
                if pattern in content_lower:
                    threats.append(pattern)
                    risk_score += 1

            is_safe = risk_score < 3

            if not is_safe:
                self.log_security_event("THREAT_DETECTED", details=f"Risk score: {risk_score}")

            return {
                'is_safe': is_safe,
                'threats': threats,
                'risk_score': risk_score,
                'recommendation': 'ALLOW' if is_safe else 'BLOCK'
            }
        
        def validate_file_upload(self, filename: str, file_size: int = 0, 
                                mime_type: str = None) -> Dict:
            """Valida upload de arquivo contra ameaças"""
            issues = []
            
            # Verificar path traversal
            if FileSecurityConfig.has_path_traversal(filename):
                issues.append("PATH_TRAVERSAL")
                self.log_security_event("PATH_TRAVERSAL_ATTEMPT", details=filename)
            
            # Verificar extensão
            if not FileSecurityConfig.is_extension_allowed(filename):
                issues.append("BLOCKED_EXTENSION")
            
            # Verificar MIME type
            if mime_type and not FileSecurityConfig.is_mime_type_allowed(mime_type):
                issues.append("BLOCKED_MIME_TYPE")
            
            # Verificar tamanho
            if file_size > FileSecurityConfig.MAX_FILE_SIZE:
                issues.append("FILE_TOO_LARGE")
            
            # Verificar nome reservado
            if FileSecurityConfig.is_reserved_filename(filename):
                issues.append("RESERVED_FILENAME")
            
            is_safe = len(issues) == 0
            
            return {
                'is_safe': is_safe,
                'issues': issues,
                'sanitized_filename': sanitize_filename(filename) if filename else None,
                'recommendation': 'ALLOW' if is_safe else 'BLOCK'
            }

    return {
        'security_middleware': security_middleware,
        'rate_limit': rate_limit,
        'get_security_manager': lambda: IntegratedSecurityManager(),
        'get_client_ip': get_client_ip,
        'apply_security_headers': security_middleware,
        'sanitize_filename': sanitize_filename,
        'file_security': FileSecurityConfig,
        'status': 'integrated'
    }

def _get_disabled_security():
    """Sistema de segurança desabilitado"""
    def noop(*args, **kwargs):
        pass

    def noop_decorator(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    def noop_sanitize(filename: str) -> str:
        return filename

    class DisabledSecurityManager:
        def log_security_event(self, *args, **kwargs):
            pass
        def check_rate_limit(self, *args, **kwargs):
            return True
        def scan_content_for_threats(self, content: str):
            return {'is_safe': True, 'threats': [], 'risk_score': 0}
        def validate_file_upload(self, *args, **kwargs):
            return {'is_safe': True, 'issues': [], 'recommendation': 'ALLOW'}

    return {
        'security_middleware': noop,
        'rate_limit': noop_decorator,
        'get_security_manager': lambda: DisabledSecurityManager(),
        'get_client_ip': lambda: "127.0.0.1",
        'apply_security_headers': noop,
        'sanitize_filename': noop_sanitize,
        'file_security': FileSecurityConfig,
        'status': 'disabled'
    }

# Verificação de upload monitor
def check_upload_monitor():
    """Verifica disponibilidade do upload monitor"""
    logger = setup_logging()

    try:
        import upload_monitor
        logger.info("✅ Upload monitor loaded")
        return True
    except ImportError:
        logger.debug("Upload monitor not found - using basic upload")
        return False

# Funções de conveniência
def initialize_security():
    """Compatibilidade - inicializa sistema de segurança"""
    result = setup_app_security()
    return result['security']

def get_security_config():
    """Compatibilidade - retorna configuração de segurança"""
    return setup_app_security()

# ===== NOVAS FUNÇÕES PARA PATH TRAVERSAL =====
def validate_file_path(filepath: str) -> bool:
    """Valida se um caminho de arquivo é seguro"""
    return not FileSecurityConfig.has_path_traversal(filepath)

def sanitize_user_filename(filename: str) -> str:
    """Sanitiza nome de arquivo fornecido pelo usuário"""
    security = initialize_security()
    if 'sanitize_filename' in security:
        return security['sanitize_filename'](filename)
    return filename

def get_file_security_config() -> FileSecurityConfig:
    """Retorna configuração de segurança de arquivos"""
    return FileSecurityConfig

# Debug simplificado
def debug_security_status():
    """Debug do sistema"""
    logger = setup_logging()

    print("\n" + "="*50)
    print("🔍 SYSTEM STATUS")
    print("="*50)

    print(f"Security: {Config.SECURITY_ENABLED}")
    print(f"Company: {Config.COMPANY_NAME}")
    print(f"File Sanitization: {Config.SANITIZE_FILENAMES}")
    print(f"Threat Scanning: {Config.SCAN_FOR_THREATS}")

    deps = check_dependencies()
    print(f"MFA: {deps['MFA_AVAILABLE']}")
    print(f"Cookies: {deps['COOKIES_AVAILABLE']}")
    print(f"Security Patches: {deps['SECURITY_PATCHES_AVAILABLE']}")
    print(f"Upload Monitor: {deps['UPLOAD_MONITOR_AVAILABLE']}")

    security_setup = setup_app_security()
    print(f"Status: {security_setup['status']}")
    
    # Testar segurança de arquivo
    print("\n📁 FILE SECURITY TEST:")
    test_files = [
        "../../../etc/passwd",
        "normal_file.pdf",
        "dangerous.exe",
        "CON.txt"
    ]
    
    for test_file in test_files:
        is_safe = not FileSecurityConfig.has_path_traversal(test_file)
        ext_allowed = FileSecurityConfig.is_extension_allowed(test_file)
        print(f"  {test_file}: Safe={is_safe}, ExtAllowed={ext_allowed}")
    
    print("✅ System operational")
    print("="*50)

# Para compatibilidade
if __name__ == "__main__":
    debug_security_status()
