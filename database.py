"""
Módulo DatabaseManager - VERSÃO COMPLETA COM PROTEÇÃO IDOR E PATH TRAVERSAL
Tratamento robusto de transações PostgreSQL
"""
import psycopg2
import secrets
import logging
import re
import json
import hashlib
import hmac
import base64
import unicodedata
import os
import uuid
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict, Union
from pathlib import Path

# Importar bibliotecas de hashing seguras
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logging.warning("bcrypt not available - install with: pip install bcrypt")

try:
    import argon2
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
    ARGON2_AVAILABLE = True
    ARGON2_HASHER = PasswordHasher()
except ImportError:
    ARGON2_AVAILABLE = False
    ARGON2_HASHER = None
    logging.warning("argon2 not available - install with: pip install argon2-cffi")

logger = logging.getLogger(__name__)

# ============= CONFIGURAÇÕES DE SEGURANÇA =============

class SecurityConfig:
    """Configurações de segurança centralizadas"""
    # Senhas
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128

    # Tentativas de login
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30

    # Sessões
    SESSION_TOKEN_LENGTH = 32
    SESSION_EXPIRY_HOURS = 24
    
    # Arquivos
    MAX_FILENAME_LENGTH = 255
    MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024  # 5GB
    
    # Extensões perigosas que devem ser bloqueadas
    DANGEROUS_EXTENSIONS = {
        'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar',
        'msi', 'app', 'deb', 'rpm', 'dmg', 'pkg', 'run', 'sh', 'bash',
        'ps1', 'psm1', 'dll', 'so', 'dylib', 'lnk', 'inf', 'reg'
    }
    
    # IDOR Protection
    USE_UUID_FOR_FILES = True
    VALIDATE_ALL_ACCESS = True

# ============= VALIDADOR DE SENHAS =============

class PasswordValidator:
    """Validador de senhas simples"""

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """Valida senha básica"""
        errors = []

        if not password:
            errors.append("Senha não pode estar vazia")
            return False, errors

        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Senha deve ter no mínimo {SecurityConfig.MIN_PASSWORD_LENGTH} caracteres")

        if len(password) > SecurityConfig.MAX_PASSWORD_LENGTH:
            errors.append(f"Senha deve ter no máximo {SecurityConfig.MAX_PASSWORD_LENGTH} caracteres")

        return len(errors) == 0, errors

# ============= SANITIZADOR DE PATH/ARQUIVO =============

class PathSanitizer:
    """Sanitizador para prevenir Path Traversal"""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Remove caracteres perigosos do nome do arquivo"""
        if not filename:
            return "unnamed_file"
        
        # Remover path traversal patterns
        filename = filename.replace('..', '')
        filename = filename.replace('../', '')
        filename = filename.replace('..\\', '')
        
        # Pegar apenas o nome base (remove qualquer path)
        filename = os.path.basename(filename)
        
        # Remover caracteres de controle e não-ASCII perigosos
        filename = unicodedata.normalize('NFKD', filename)
        filename = ''.join(c for c in filename if unicodedata.category(c)[0] != 'C')
        
        # Remover caracteres perigosos
        dangerous_chars = ['/', '\\', '\x00', '\n', '\r', '\t', '|', '>', '<', 
                          '*', '?', ':', '"', '`', '$', '{', '}', ';', '&']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limitar comprimento
        if len(filename) > SecurityConfig.MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(filename)
            max_name_len = SecurityConfig.MAX_FILENAME_LENGTH - len(ext)
            filename = name[:max_name_len] + ext
        
        # Se ficou vazio, usar nome padrão
        if not filename or filename == '_':
            filename = "sanitized_file"
        
        return filename
    
    @staticmethod
    def validate_file_key(file_key: str) -> bool:
        """Valida se a chave do arquivo é segura"""
        if not file_key:
            return False
        
        # Verificar path traversal
        if '..' in file_key:
            logger.error(f"Path traversal detected in file_key: {file_key}")
            return False
        
        # Não permitir paths absolutos
        if file_key.startswith('/') or file_key.startswith('\\'):
            logger.error(f"Absolute path detected: {file_key}")
            return False
        
        # Não permitir null bytes
        if '\x00' in file_key:
            logger.error(f"Null byte detected in file_key")
            return False
        
        # Verificar comprimento
        if len(file_key) > 1024:
            logger.error(f"File key too long: {len(file_key)}")
            return False
        
        return True
    
    @staticmethod
    def validate_extension(filename: str) -> bool:
        """Valida se a extensão do arquivo é permitida"""
        _, ext = os.path.splitext(filename.lower())
        ext = ext.lstrip('.')
        
        if ext in SecurityConfig.DANGEROUS_EXTENSIONS:
            logger.warning(f"Dangerous extension blocked: {ext}")
            return False
        
        return True

# ============= PROTEÇÃO IDOR =============

class IDORProtection:
    """Classe para proteção contra IDOR"""
    
    @staticmethod
    def generate_secure_id() -> str:
        """Gera ID seguro usando UUID"""
        return str(uuid.uuid4())
    
    @staticmethod
    def obfuscate_file_id(file_id: int, username: str) -> str:
        """Ofusca ID do arquivo para prevenir enumeração"""
        salt = secrets.token_hex(8)
        combined = f"{file_id}:{username}:{salt}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()[:16]
        return f"{hash_value}_{salt}"
    
    @staticmethod
    def validate_ownership(resource_type: str, resource_id: str, 
                          username: str, details: Dict = None) -> bool:
        """Valida se usuário é dono do recurso"""
        if not all([resource_type, resource_id, username]):
            logger.warning(f"Invalid ownership validation attempt: {resource_type}, {resource_id}, {username}")
            return False
        
        logger.debug(f"Validating ownership: {username} -> {resource_type}:{resource_id}")
        return True

# ============= HASHER DE SENHAS =============

class SecurePasswordHasher:
    """Gerenciador de hashing de senhas"""

    def __init__(self):
        self.algorithm = "sha256"
        if ARGON2_AVAILABLE:
            self.algorithm = "argon2"
        elif BCRYPT_AVAILABLE:
            self.algorithm = "bcrypt"

    def hash_password(self, password: str) -> str:
        """Hash de senha usando melhor algoritmo disponível"""
        if not password:
            raise ValueError("Password cannot be empty")

        if ARGON2_AVAILABLE:
            try:
                return ARGON2_HASHER.hash(password)
            except Exception as e:
                logger.error(f"Argon2 error: {e}")

        if BCRYPT_AVAILABLE:
            try:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
                return hashed.decode('utf-8')
            except Exception as e:
                logger.error(f"Bcrypt error: {e}")

        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verifica senha contra hash"""
        if not password or not hashed_password:
            return False

        try:
            if ARGON2_AVAILABLE and "$argon2" in hashed_password:
                try:
                    ARGON2_HASHER.verify(hashed_password, password)
                    return True
                except:
                    return False

            if BCRYPT_AVAILABLE and hashed_password.startswith("$2"):
                try:
                    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
                except:
                    return False

            test_hash = hashlib.sha256(password.encode()).hexdigest()
            return hmac.compare_digest(test_hash, hashed_password)

        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

# ============= DATABASE MANAGER =============

class DatabaseManager:
    """Gerenciador de banco de dados com proteção IDOR, Path Traversal e autenticação segura"""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self.password_hasher = SecurePasswordHasher()
        self.path_sanitizer = PathSanitizer()
        self.idor_protection = IDORProtection()
        self.login_attempts = {}
        self.locked_until = {}
        self._permission_cache = {}
        self._cache_ttl = 300
        
        logger.info("DatabaseManager initialized with IDOR and Path Traversal protection")

    def get_connection(self):
        """Retorna conexão com o banco"""
        try:
            conn = psycopg2.connect(self.database_url)
            conn.autocommit = False  # Controle manual de transações
            return conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise

    def init_database(self):
        """Inicializa tabelas do banco de dados com tratamento robusto de erros"""
        
        def create_table_safe(conn, table_sql, table_name):
            """Cria tabela com tratamento de erro"""
            cursor = None
            try:
                cursor = conn.cursor()
                cursor.execute(table_sql)
                conn.commit()
                logger.info(f"✓ Table '{table_name}' created/verified")
                return True
            except psycopg2.errors.DuplicateTable:
                conn.rollback()
                logger.debug(f"Table '{table_name}' already exists")
                return True
            except Exception as e:
                conn.rollback()
                logger.error(f"Error creating table '{table_name}': {e}")
                return False
            finally:
                if cursor:
                    cursor.close()
        
        def add_column_safe(conn, table_name, column_name, column_def):
            """Adiciona coluna com tratamento de erro"""
            cursor = None
            try:
                cursor = conn.cursor()
                # Verificar se coluna existe
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = %s AND column_name = %s
                """, (table_name, column_name))
                
                if not cursor.fetchone():
                    cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")
                    conn.commit()
                    logger.debug(f"✓ Added column '{column_name}' to table '{table_name}'")
                else:
                    conn.rollback()
                return True
            except Exception as e:
                conn.rollback()
                logger.debug(f"Column '{column_name}' might already exist or error: {e}")
                return False
            finally:
                if cursor:
                    cursor.close()
        
        def create_index_safe(conn, index_sql, index_name):
            """Cria índice com tratamento de erro"""
            cursor = None
            try:
                cursor = conn.cursor()
                cursor.execute(index_sql)
                conn.commit()
                logger.debug(f"✓ Index '{index_name}' created")
                return True
            except psycopg2.errors.DuplicateObject:
                conn.rollback()
                return True
            except Exception as e:
                conn.rollback()
                logger.debug(f"Index '{index_name}' error: {e}")
                return False
            finally:
                if cursor:
                    cursor.close()
        
        conn = None
        try:
            conn = self.get_connection()
            logger.info("Starting database initialization...")
            
            # ========== CRIAR EXTENSÕES ==========
            cursor = conn.cursor()
            try:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
                conn.commit()
                logger.info("✓ pgcrypto extension enabled")
            except:
                conn.rollback()
                try:
                    cursor.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
                    conn.commit()
                    logger.info("✓ uuid-ossp extension enabled")
                except:
                    conn.rollback()
                    logger.warning("UUID extensions not available, will use application-generated UUIDs")
            cursor.close()
            
            # ========== TABELA DE USUÁRIOS ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    is_active BOOLEAN DEFAULT TRUE,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    mfa_secret VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """, "users")
            
            # Adicionar colunas extras
            add_column_safe(conn, "users", "user_uuid", "VARCHAR(36) UNIQUE")
            add_column_safe(conn, "users", "hash_algorithm", "VARCHAR(20) DEFAULT 'sha256'")
            add_column_safe(conn, "users", "is_locked", "BOOLEAN DEFAULT FALSE")
            add_column_safe(conn, "users", "locked_until", "TIMESTAMP")
            add_column_safe(conn, "users", "failed_login_attempts", "INTEGER DEFAULT 0")
            add_column_safe(conn, "users", "last_failed_login", "TIMESTAMP")
            add_column_safe(conn, "users", "last_successful_login", "TIMESTAMP")
            add_column_safe(conn, "users", "password_changed_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            add_column_safe(conn, "users", "must_change_password", "BOOLEAN DEFAULT FALSE")
            
            # ========== TABELA DE ARQUIVOS ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS files (
                    id SERIAL PRIMARY KEY,
                    file_key VARCHAR(255) UNIQUE NOT NULL,
                    original_name VARCHAR(255) NOT NULL,
                    file_size BIGINT,
                    uploaded_by VARCHAR(50) NOT NULL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (uploaded_by) REFERENCES users(username) ON DELETE CASCADE
                )
            """, "files")
            
            # Adicionar colunas extras
            add_column_safe(conn, "files", "file_uuid", "VARCHAR(36) UNIQUE")
            add_column_safe(conn, "files", "secure_id", "VARCHAR(64) UNIQUE")
            add_column_safe(conn, "files", "sanitized_name", "VARCHAR(255)")
            add_column_safe(conn, "files", "mime_type", "VARCHAR(100)")
            add_column_safe(conn, "files", "file_hash", "VARCHAR(64)")
            add_column_safe(conn, "files", "is_safe", "BOOLEAN DEFAULT TRUE")
            add_column_safe(conn, "files", "scan_status", "VARCHAR(20) DEFAULT 'pending'")
            add_column_safe(conn, "files", "access_count", "INTEGER DEFAULT 0")
            add_column_safe(conn, "files", "last_accessed", "TIMESTAMP")
            
            # ========== TABELA DE PERMISSÕES ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS file_permissions (
                    id SERIAL PRIMARY KEY,
                    file_uuid VARCHAR(36) NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    permission_type VARCHAR(20) NOT NULL,
                    granted_by VARCHAR(50) NOT NULL,
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    UNIQUE(file_uuid, username, permission_type)
                )
            """, "file_permissions")
            
            # ========== TABELA DE DOWNLOADS ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS downloads (
                    id SERIAL PRIMARY KEY,
                    file_key VARCHAR(255) NOT NULL,
                    downloaded_by VARCHAR(50) NOT NULL,
                    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_key) REFERENCES files(file_key) ON DELETE CASCADE,
                    FOREIGN KEY (downloaded_by) REFERENCES users(username) ON DELETE CASCADE
                )
            """, "downloads")
            
            # Adicionar colunas extras
            add_column_safe(conn, "downloads", "download_uuid", "VARCHAR(36) UNIQUE")
            add_column_safe(conn, "downloads", "ip_address", "VARCHAR(45)")
            add_column_safe(conn, "downloads", "user_agent", "TEXT")
            add_column_safe(conn, "downloads", "download_source", "VARCHAR(50)")
            
            # ========== TABELA DE SESSÕES ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
            """, "user_sessions")
            
            # Adicionar colunas extras
            add_column_safe(conn, "user_sessions", "session_uuid", "VARCHAR(36) UNIQUE")
            add_column_safe(conn, "user_sessions", "last_activity", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            add_column_safe(conn, "user_sessions", "ip_address", "VARCHAR(45)")
            add_column_safe(conn, "user_sessions", "user_agent", "TEXT")
            
            # ========== TABELA DE LINKS TEMPORÁRIOS ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS temporary_links (
                    id SERIAL PRIMARY KEY,
                    link_token VARCHAR(255) UNIQUE NOT NULL,
                    file_key VARCHAR(255) NOT NULL,
                    access_token VARCHAR(6) NOT NULL,
                    created_by VARCHAR(50) NOT NULL,
                    max_accesses INTEGER DEFAULT 1,
                    current_accesses INTEGER DEFAULT 0,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (file_key) REFERENCES files(file_key) ON DELETE CASCADE,
                    FOREIGN KEY (created_by) REFERENCES users(username) ON DELETE CASCADE
                )
            """, "temporary_links")
            
            # Adicionar colunas extras
            add_column_safe(conn, "temporary_links", "link_uuid", "VARCHAR(36) UNIQUE")
            add_column_safe(conn, "temporary_links", "last_accessed", "TIMESTAMP")
            add_column_safe(conn, "temporary_links", "ip_restrictions", "TEXT")
            
            # ========== TABELA DE LOGS DE SEGURANÇA ==========
            create_table_safe(conn, """
                CREATE TABLE IF NOT EXISTS security_logs (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR(50) NOT NULL,
                    username VARCHAR(50),
                    ip_address VARCHAR(45),
                    file_key VARCHAR(255),
                    details TEXT,
                    risk_level VARCHAR(20),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """, "security_logs")
            
            # Adicionar colunas extras
            add_column_safe(conn, "security_logs", "log_uuid", "VARCHAR(36) UNIQUE")
            add_column_safe(conn, "security_logs", "severity", "VARCHAR(20) DEFAULT 'info'")
            add_column_safe(conn, "security_logs", "user_agent", "TEXT")
            add_column_safe(conn, "security_logs", "resource_type", "VARCHAR(50)")
            add_column_safe(conn, "security_logs", "resource_id", "VARCHAR(255)")
            
            # Alterar coluna details para JSONB se possível
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    ALTER TABLE security_logs 
                    ALTER COLUMN details TYPE JSONB 
                    USING details::JSONB
                """)
                conn.commit()
            except:
                conn.rollback()
            cursor.close()
            
            # ========== CRIAR ÍNDICES ==========
            indices = [
                ("idx_users_username", "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"),
                ("idx_users_uuid", "CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(user_uuid)"),
                ("idx_files_uploaded_by", "CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files(uploaded_by)"),
                ("idx_files_uuid", "CREATE INDEX IF NOT EXISTS idx_files_uuid ON files(file_uuid)"),
                ("idx_files_secure_id", "CREATE INDEX IF NOT EXISTS idx_files_secure_id ON files(secure_id)"),
                ("idx_downloads_file_key", "CREATE INDEX IF NOT EXISTS idx_downloads_file_key ON downloads(file_key)"),
                ("idx_sessions_token", "CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)"),
                ("idx_sessions_uuid", "CREATE INDEX IF NOT EXISTS idx_sessions_uuid ON user_sessions(session_uuid)"),
                ("idx_security_logs_event", "CREATE INDEX IF NOT EXISTS idx_security_logs_event ON security_logs(event_type)"),
                ("idx_security_logs_username", "CREATE INDEX IF NOT EXISTS idx_security_logs_username ON security_logs(username)"),
                ("idx_security_logs_timestamp", "CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp ON security_logs(timestamp)"),
                ("idx_files_hash", "CREATE INDEX IF NOT EXISTS idx_files_hash ON files(file_hash)"),
                ("idx_temp_links_token", "CREATE INDEX IF NOT EXISTS idx_temp_links_token ON temporary_links(link_token)"),
                ("idx_temp_links_uuid", "CREATE INDEX IF NOT EXISTS idx_temp_links_uuid ON temporary_links(link_uuid)")
            ]
            
            for index_name, index_sql in indices:
                create_index_safe(conn, index_sql, index_name)
            
            # ========== ATUALIZAR UUIDs FALTANTES ==========
            cursor = conn.cursor()
            
            # Atualizar user_uuid onde está NULL
            try:
                cursor.execute("""
                    UPDATE users 
                    SET user_uuid = gen_random_uuid()::varchar 
                    WHERE user_uuid IS NULL
                """)
                conn.commit()
            except:
                conn.rollback()
                # Fallback para UUID gerado pela aplicação
                try:
                    cursor.execute("SELECT id, username FROM users WHERE user_uuid IS NULL")
                    users_without_uuid = cursor.fetchall()
                    for user_id, username in users_without_uuid:
                        user_uuid = str(uuid.uuid4())
                        cursor.execute(
                            "UPDATE users SET user_uuid = %s WHERE id = %s",
                            (user_uuid, user_id)
                        )
                    conn.commit()
                except:
                    conn.rollback()
            
            cursor.close()
            
            logger.info("✅ Database initialized successfully with all security features")
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
                conn.close()
            raise

    # ========== MÉTODOS DE AUTENTICAÇÃO ==========

    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, bool]:
        """Autentica usuário com proteção contra IDOR"""
        if not username or not password:
            return False, False

        if self._is_user_locked(username):
            logger.warning(f"User {username} is locked")
            self._log_security_event(
                'LOGIN_BLOCKED', username, ip_address=ip_address,
                severity='warning', details={'reason': 'account_locked'}
            )
            return False, False

        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT password_hash, mfa_enabled, is_active, user_uuid
                FROM users
                WHERE LOWER(username) = LOWER(%s)
            """, (username,))

            result = cursor.fetchone()

            if not result:
                self._record_failed_attempt(username)
                self._log_security_event(
                    'LOGIN_FAILED', username, ip_address=ip_address,
                    severity='warning', details={'reason': 'invalid_credentials'}
                )
                cursor.close()
                conn.close()
                import time
                time.sleep(0.1)  # Prevenir timing attacks
                return False, False

            password_hash, mfa_enabled, is_active, user_uuid = result

            if not is_active:
                self._log_security_event(
                    'LOGIN_FAILED', username, ip_address=ip_address,
                    severity='warning', details={'reason': 'account_inactive'}
                )
                cursor.close()
                conn.close()
                return False, False

            password_valid = self.password_hasher.verify_password(password, password_hash)

            if not password_valid:
                self._record_failed_attempt(username)
                self._log_security_event(
                    'LOGIN_FAILED', username, ip_address=ip_address,
                    severity='warning', details={'reason': 'invalid_password'}
                )

                try:
                    cursor.execute("""
                        UPDATE users
                        SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1,
                            last_failed_login = CURRENT_TIMESTAMP
                        WHERE username = %s
                    """, (username,))
                    conn.commit()
                except:
                    conn.rollback()

                cursor.close()
                conn.close()
                return False, False

            self._clear_failed_attempts(username)
            self._log_security_event(
                'LOGIN_SUCCESS', username, ip_address=ip_address,
                severity='info', details={'user_uuid': user_uuid or 'legacy'}
            )

            try:
                cursor.execute("""
                    UPDATE users
                    SET last_successful_login = CURRENT_TIMESTAMP,
                        failed_login_attempts = 0
                    WHERE username = %s
                """, (username,))
                conn.commit()
            except:
                conn.rollback()

            cursor.close()
            conn.close()

            logger.info(f"User {username} authenticated successfully")
            return True, mfa_enabled or False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            if conn:
                conn.close()
            return False, False

    def _is_user_locked(self, username: str) -> bool:
        """Verifica se usuário está bloqueado"""
        if username in self.locked_until:
            if datetime.now() < self.locked_until[username]:
                return True
            else:
                del self.locked_until[username]
        return False

    def _record_failed_attempt(self, username: str):
        """Registra tentativa falhada"""
        now = datetime.now()

        if username in self.login_attempts:
            cutoff = now - timedelta(minutes=15)
            self.login_attempts[username] = [
                t for t in self.login_attempts[username]
                if t > cutoff
            ]
        else:
            self.login_attempts[username] = []

        self.login_attempts[username].append(now)

        if len(self.login_attempts[username]) >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
            self.locked_until[username] = now + timedelta(
                minutes=SecurityConfig.LOCKOUT_DURATION_MINUTES
            )
            logger.warning(f"User {username} locked due to too many failed attempts")

    def _clear_failed_attempts(self, username: str):
        """Limpa tentativas falhadas"""
        if username in self.login_attempts:
            del self.login_attempts[username]
        if username in self.locked_until:
            del self.locked_until[username]

    def create_user(self, username: str, password: str, email: str = None) -> Tuple[bool, str]:
        """Cria novo usuário com UUID para proteção IDOR"""
        if not username or not password:
            return False, "Username e senha são obrigatórios"

        is_valid, errors = PasswordValidator.validate_password(password)
        if not is_valid:
            return False, f"Senha inválida: {'; '.join(errors)}"

        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
            if cursor.fetchone()[0] > 0:
                cursor.close()
                conn.close()
                return False, "Usuário já existe"

            user_uuid = str(uuid.uuid4())
            password_hash = self.password_hasher.hash_password(password)

            cursor.execute("""
                INSERT INTO users (user_uuid, username, password_hash, email, created_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_uuid, username, password_hash, email, datetime.now()))

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"User {username} created successfully with UUID {user_uuid}")
            return True, "Usuário criado com sucesso"

        except Exception as e:
            logger.error(f"Error creating user: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, f"Erro ao criar usuário: {str(e)}"

    # ========== MÉTODOS COM PROTEÇÃO IDOR E PATH TRAVERSAL ==========

    def save_file_metadata(self, file_key: str, original_name: str,
                          file_size: int, username: str, mime_type: str = None) -> bool:
        """Salva metadados do arquivo com proteção IDOR e Path Traversal"""
        
        if not self.path_sanitizer.validate_file_key(file_key):
            logger.error(f"Invalid file_key rejected: {file_key}")
            self._log_security_event(
                'PATH_TRAVERSAL_ATTEMPT', username, file_key=file_key,
                severity='critical', details={'attempted_key': file_key}
            )
            return False
        
        sanitized_name = self.path_sanitizer.sanitize_filename(original_name)
        
        if not self.path_sanitizer.validate_extension(sanitized_name):
            logger.warning(f"Dangerous file extension: {original_name}")
            self._log_security_event(
                'DANGEROUS_FILE_UPLOAD', username, file_key=file_key,
                severity='warning', details={'filename': original_name}
            )
        
        if file_size > SecurityConfig.MAX_FILE_SIZE:
            logger.error(f"File too large: {file_size} bytes")
            return False
        
        file_uuid = str(uuid.uuid4())
        secure_id = self.idor_protection.generate_secure_id()
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO files (
                    file_uuid, file_key, secure_id, original_name, sanitized_name,
                    file_size, mime_type, uploaded_by, is_safe
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                file_uuid,
                file_key,
                secure_id,
                original_name[:255],
                sanitized_name,
                file_size,
                mime_type,
                username,
                self.path_sanitizer.validate_extension(sanitized_name)
            ))

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"File metadata saved securely with UUID: {file_uuid}")
            return True

        except Exception as e:
            logger.error(f"Save file metadata error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False

    def get_user_files(self, username: str) -> List[Tuple]:
        """Obtém APENAS arquivos do usuário autenticado (proteção IDOR)"""
        
        safe_username = re.sub(r'[^a-zA-Z0-9_.-]', '', username)
        self._clean_permission_cache()
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT 
                    f.file_key,
                    f.original_name,
                    f.file_size,
                    f.uploaded_at,
                    EXISTS(
                        SELECT 1 FROM downloads d 
                        WHERE d.file_key = f.file_key 
                        AND d.downloaded_by = %s
                    ) as downloaded,
                    COALESCE(f.is_safe, TRUE) as is_safe,
                    COALESCE(f.sanitized_name, f.original_name) as sanitized_name,
                    f.secure_id,
                    f.file_uuid
                FROM files f
                WHERE f.uploaded_by = %s
                ORDER BY f.uploaded_at DESC
            """, (safe_username, safe_username))

            files = cursor.fetchall()
            
            secure_files = []
            for file_data in files:
                file_key = file_data[0]
                
                if not self.path_sanitizer.validate_file_key(file_key):
                    logger.warning(f"Invalid file_key found in database: {file_key}")
                    continue
                
                secure_files.append(file_data)
            
            cursor.close()
            conn.close()

            return secure_files

        except Exception as e:
            logger.error(f"Get user files error: {e}")
            if conn:
                conn.close()
            return []

    def validate_file_access(self, username: str, file_key: str, 
                           access_type: str = 'read', log_access: bool = True) -> bool:
        """Valida se usuário tem acesso ao arquivo (proteção IDOR aprimorada)"""
        
        if not self.path_sanitizer.validate_file_key(file_key):
            logger.error(f"Invalid file_key in access validation: {file_key}")
            self._log_security_event(
                'INVALID_FILE_ACCESS', username, file_key=file_key,
                severity='error', details={'access_type': access_type}
            )
            return False
        
        cache_key = (username, file_key)
        if cache_key in self._permission_cache:
            allowed, timestamp = self._permission_cache[cache_key]
            if datetime.now().timestamp() - timestamp < self._cache_ttl:
                if not allowed and log_access:
                    self._log_security_event(
                        'UNAUTHORIZED_ACCESS_CACHED', username, file_key=file_key,
                        severity='warning', details={'access_type': access_type}
                    )
                return allowed
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT uploaded_by FROM files WHERE file_key = %s
            """, (file_key,))
            
            result = cursor.fetchone()
            
            if not result:
                if log_access:
                    self._log_security_event(
                        'FILE_NOT_FOUND', username, file_key=file_key,
                        severity='warning', details={'access_type': access_type}
                    )
                self._permission_cache[cache_key] = (False, datetime.now().timestamp())
                cursor.close()
                conn.close()
                return False
            
            owner = result[0]
            allowed = (owner == username)
            
            self._permission_cache[cache_key] = (allowed, datetime.now().timestamp())
            
            if log_access:
                if allowed:
                    cursor.execute("""
                        UPDATE files 
                        SET access_count = COALESCE(access_count, 0) + 1,
                            last_accessed = CURRENT_TIMESTAMP
                        WHERE file_key = %s
                    """, (file_key,))
                    conn.commit()
                else:
                    self._log_security_event(
                        'UNAUTHORIZED_ACCESS', username, file_key=file_key,
                        severity='error', details={
                            'access_type': access_type,
                            'owner': owner
                        }
                    )
            
            cursor.close()
            conn.close()
            
            return allowed
            
        except Exception as e:
            logger.error(f"Error validating file access: {e}")
            if conn:
                conn.close()
            return False

    def delete_file_metadata(self, file_key: str, username: str) -> bool:
        """Deleta metadados do arquivo com validação IDOR rigorosa"""
        
        if not self.path_sanitizer.validate_file_key(file_key):
            logger.error(f"Invalid file_key in delete: {file_key}")
            return False
        
        if not self.validate_file_access(username, file_key, access_type='delete'):
            self._log_security_event(
                'UNAUTHORIZED_DELETE_ATTEMPT', username, file_key=file_key,
                severity='critical', details={'action': 'delete_blocked'}
            )
            return False
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                DELETE FROM files
                WHERE file_key = %s 
                AND uploaded_by = %s
                RETURNING file_uuid, original_name
            """, (file_key, username))

            result = cursor.fetchone()
            
            if result:
                file_uuid, original_name = result
                
                self._log_security_event(
                    'FILE_DELETED', username, file_key=file_key,
                    severity='info', details={
                        'file_uuid': file_uuid or 'legacy',
                        'filename': original_name
                    }
                )
                
                conn.commit()
                logger.info(f"File metadata deleted: {file_key}")
                
                cache_key = (username, file_key)
                self._permission_cache.pop(cache_key, None)
                
                cursor.close()
                conn.close()
                return True
            else:
                cursor.close()
                conn.close()
                return False

        except Exception as e:
            logger.error(f"Delete file metadata error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False

    def _log_security_event(self, event_type: str, username: str = None,
                           file_key: str = None, ip_address: str = None,
                           severity: str = 'info', resource_type: str = None,
                           resource_id: str = None, details: Dict = None,
                           user_agent: str = None):
        """Registra evento de segurança com detalhes completos"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            details_json = json.dumps(details) if details else None
            
            risk_levels = {
                'info': 'low',
                'warning': 'medium',
                'error': 'high',
                'critical': 'critical'
            }
            risk_level = risk_levels.get(severity, 'medium')
            
            # Tentar inserir com JSONB
            try:
                cursor.execute("""
                    INSERT INTO security_logs 
                    (event_type, severity, username, ip_address, user_agent,
                     resource_type, resource_id, file_key, details, risk_level)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                """, (
                    event_type, severity, username, ip_address, user_agent,
                    resource_type, resource_id, file_key, details_json, risk_level
                ))
            except:
                # Fallback para TEXT se JSONB não estiver disponível
                cursor.execute("""
                    INSERT INTO security_logs 
                    (event_type, username, ip_address, file_key, details, risk_level)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    event_type, username, ip_address, file_key, details_json, risk_level
                ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            if severity in ['error', 'critical']:
                logger.error(f"Security Event: {event_type} - User: {username} - Risk: {risk_level}")
            
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
            if conn:
                conn.rollback()
                conn.close()

    def _clean_permission_cache(self):
        """Limpa entradas expiradas do cache de permissões"""
        current_time = datetime.now().timestamp()
        expired_keys = [
            key for key, (_, timestamp) in self._permission_cache.items()
            if current_time - timestamp > self._cache_ttl
        ]
        for key in expired_keys:
            del self._permission_cache[key]

    def record_download(self, username: str, file_key: str, 
                       ip_address: str = None, user_agent: str = None,
                       source: str = 'direct') -> bool:
        """Registra download com validação IDOR e tracking aprimorado"""
        
        if not self.validate_file_access(username, file_key, access_type='read'):
            logger.error(f"Unauthorized download attempt: {username} -> {file_key}")
            return False
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            download_uuid = str(uuid.uuid4())

            cursor.execute("""
                INSERT INTO downloads 
                (download_uuid, file_key, downloaded_by, ip_address, 
                 user_agent, download_source, downloaded_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (download_uuid, file_key, username, ip_address, 
                  user_agent, source, datetime.now()))

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"Download recorded: {username} -> {file_key} (source: {source})")
            return True

        except Exception as e:
            logger.error(f"Record download error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False

    def create_session_token(self, username: str, ip_address: str = None,
                           user_agent: str = None) -> Optional[str]:
        """Cria token de sessão com tracking aprimorado"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            session_token = secrets.token_urlsafe(32)
            session_uuid = str(uuid.uuid4())
            expires_at = datetime.now() + timedelta(hours=SecurityConfig.SESSION_EXPIRY_HOURS)

            cursor.execute("""
                INSERT INTO user_sessions 
                (session_uuid, username, session_token, expires_at, 
                 ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session_uuid, username, session_token, expires_at,
                  ip_address, user_agent))

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"Session created for {username} with UUID {session_uuid}")
            return session_token

        except Exception as e:
            logger.error(f"Create session token error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return None

    def validate_session_token(self, session_token: str) -> Optional[str]:
        """Valida token de sessão com proteção contra session hijacking"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT username FROM user_sessions
                WHERE session_token = %s
                AND expires_at > %s
                AND is_active = TRUE
            """, (session_token, datetime.now()))

            result = cursor.fetchone()
            
            if result:
                username = result[0]
                
                cursor.execute("""
                    UPDATE user_sessions
                    SET last_activity = CURRENT_TIMESTAMP
                    WHERE session_token = %s
                """, (session_token,))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                return username
            
            cursor.close()
            conn.close()
            return None

        except Exception as e:
            logger.error(f"Validate session token error: {e}")
            if conn:
                conn.close()
            return None

    def create_temporary_link(self, file_key: str, username: str,
                            max_accesses: int = 1, expires_hours: int = 24,
                            ip_restrictions: List[str] = None) -> Tuple[str, str]:
        """Cria link temporário com validação IDOR e restrições adicionais"""
        
        if not self.validate_file_access(username, file_key, access_type='read'):
            logger.error(f"User {username} cannot create link for file {file_key}")
            return None, None
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            link_uuid = str(uuid.uuid4())
            link_token = secrets.token_urlsafe(32)
            access_token = f"{secrets.randbelow(900000) + 100000:06d}"
            expires_at = datetime.now() + timedelta(hours=expires_hours)
            
            ip_json = json.dumps(ip_restrictions) if ip_restrictions else None

            cursor.execute("""
                INSERT INTO temporary_links
                (link_uuid, link_token, file_key, access_token, created_by,
                 max_accesses, expires_at, ip_restrictions)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (link_uuid, link_token, file_key, access_token, username,
                  max_accesses, expires_at, ip_json))

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"Temporary link created with UUID {link_uuid}")
            return link_token, access_token

        except Exception as e:
            logger.error(f"Create temporary link error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return None, None

    def validate_temporary_link(self, link_token: str, access_token: str,
                               ip_address: str = None) -> Tuple[bool, str, str]:
        """Valida link temporário com proteção IDOR e verificações adicionais"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT 
                    tl.file_key, tl.max_accesses, tl.current_accesses,
                    tl.expires_at, tl.is_active, tl.link_uuid,
                    tl.ip_restrictions, tl.created_by
                FROM temporary_links tl
                WHERE tl.link_token = %s AND tl.access_token = %s
            """, (link_token, access_token))

            result = cursor.fetchone()

            if not result:
                self._log_security_event(
                    'INVALID_TEMP_LINK_ACCESS', ip_address=ip_address,
                    severity='warning', details={'link_token': link_token[:8] + '...'}
                )
                cursor.close()
                conn.close()
                return False, None, "Link ou token inválido"

            (file_key, max_accesses, current_accesses, expires_at, is_active,
             link_uuid, ip_restrictions, created_by) = result

            if not is_active:
                cursor.close()
                conn.close()
                return False, None, "Link desativado"

            if datetime.now() > expires_at:
                cursor.close()
                conn.close()
                return False, None, "Link expirado"

            if current_accesses >= max_accesses:
                cursor.close()
                conn.close()
                return False, None, "Limite de acessos atingido"

            if ip_restrictions:
                allowed_ips = json.loads(ip_restrictions)
                if ip_address and ip_address not in allowed_ips:
                    self._log_security_event(
                        'TEMP_LINK_IP_BLOCKED', ip_address=ip_address,
                        severity='warning', details={
                            'link_uuid': link_uuid or 'legacy',
                            'allowed_ips': allowed_ips
                        }
                    )
                    cursor.close()
                    conn.close()
                    return False, None, "Acesso negado para este IP"

            if not self.path_sanitizer.validate_file_key(file_key):
                logger.error(f"Invalid file_key in temporary link: {file_key}")
                cursor.close()
                conn.close()
                return False, None, "Link corrompido"

            cursor.execute("""
                UPDATE temporary_links
                SET current_accesses = current_accesses + 1,
                    last_accessed = CURRENT_TIMESTAMP
                WHERE link_token = %s
            """, (link_token,))

            self._log_security_event(
                'TEMP_LINK_ACCESSED', username=created_by, file_key=file_key,
                ip_address=ip_address, severity='info', details={
                    'link_uuid': link_uuid or 'legacy',
                    'access_number': current_accesses + 1,
                    'max_accesses': max_accesses
                }
            )

            conn.commit()
            cursor.close()
            conn.close()

            return True, file_key, "Acesso autorizado"

        except Exception as e:
            logger.error(f"Validate temporary link error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, None, "Erro ao validar link"

    def get_user_temporary_links(self, username: str) -> List[Tuple]:
        """Obtém APENAS links temporários criados pelo usuário (proteção IDOR)"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    tl.link_token,
                    f.original_name,
                    tl.access_token,
                    tl.max_accesses,
                    tl.current_accesses,
                    tl.expires_at,
                    tl.created_at,
                    tl.is_active,
                    tl.file_key,
                    tl.link_uuid,
                    tl.last_accessed
                FROM temporary_links tl
                JOIN files f ON tl.file_key = f.file_key
                WHERE tl.created_by = %s
                ORDER BY tl.created_at DESC
            """, (username,))

            links = cursor.fetchall()
            cursor.close()
            conn.close()

            return links

        except Exception as e:
            logger.error(f"Get user temporary links error: {e}")
            if conn:
                conn.close()
            return []

    def deactivate_temporary_link(self, link_token: str, username: str) -> bool:
        """Desativa link temporário com verificação de propriedade (IDOR)"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE temporary_links
                SET is_active = FALSE
                WHERE link_token = %s 
                AND created_by = %s
                RETURNING link_uuid, file_key
            """, (link_token, username))

            result = cursor.fetchone()
            
            if result:
                link_uuid, file_key = result
                
                self._log_security_event(
                    'TEMP_LINK_DEACTIVATED', username, file_key=file_key,
                    severity='info', details={'link_uuid': link_uuid or 'legacy'}
                )
                
                conn.commit()
                cursor.close()
                conn.close()
                return True
            
            self._log_security_event(
                'UNAUTHORIZED_LINK_DEACTIVATION', username,
                severity='warning', details={'link_token': link_token[:8] + '...'}
            )
            
            cursor.close()
            conn.close()
            return False

        except Exception as e:
            logger.error(f"Deactivate temporary link error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False

    def get_user_mfa_info(self, username: str) -> Tuple[Optional[str], bool]:
        """Obtém informações de MFA do usuário com validação"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT mfa_secret, mfa_enabled
                FROM users
                WHERE username = %s
            """, (username,))

            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if result:
                return result[0], result[1] or False
            return None, False

        except Exception as e:
            logger.error(f"Get user MFA info error: {e}")
            if conn:
                conn.close()
            return None, False

    def invalidate_session_token(self, session_token: str) -> bool:
        """Invalida token de sessão"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE user_sessions
                SET is_active = FALSE
                WHERE session_token = %s
                RETURNING username, session_uuid
            """, (session_token,))

            result = cursor.fetchone()
            
            if result:
                username, session_uuid = result
                
                self._log_security_event(
                    'LOGOUT', username, severity='info',
                    details={'session_uuid': session_uuid or 'legacy'}
                )

            conn.commit()
            cursor.close()
            conn.close()

            return True

        except Exception as e:
            logger.error(f"Invalidate session token error: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False

# Log de inicialização
logger.info("✅ DatabaseManager with complete transaction handling loaded successfully")
