"""
Sistema de Gerenciamento de Usuários - VERSÃO CORRIGIDA PARA FOREIGN KEY
Arquivo: user_management.py - Corrige ordem de deleção para respeitar constraints
"""
import logging
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum
import json

logger = logging.getLogger(__name__)

class Permission(Enum):
    """Enum para permissões do sistema"""
    VIEW_USERS = "view_users"
    CREATE_USERS = "create_users"
    UPDATE_USERS = "update_users"
    DELETE_USERS = "delete_users"
    MANAGE_ROLES = "manage_roles"
    VIEW_ADMIN_PANEL = "view_admin_panel"
    VIEW_REPORTS = "view_reports"
    MANAGE_SYSTEM = "manage_system"

class UserManager:
    """Classe principal para gerenciamento de usuários"""
    
    def __init__(self, db_manager, s3_manager=None):
        self.db_manager = db_manager
        self.s3_manager = s3_manager
        self.logger = logging.getLogger(__name__)
        
        # Mapeamento de roles para permissões
        self.role_permissions = {
            'super_admin': [
                Permission.VIEW_USERS, Permission.CREATE_USERS, Permission.UPDATE_USERS,
                Permission.DELETE_USERS, Permission.MANAGE_ROLES, Permission.VIEW_ADMIN_PANEL,
                Permission.VIEW_REPORTS, Permission.MANAGE_SYSTEM
            ],
            'admin': [
                Permission.VIEW_USERS, Permission.CREATE_USERS, Permission.UPDATE_USERS,
                Permission.DELETE_USERS, Permission.VIEW_ADMIN_PANEL, Permission.VIEW_REPORTS
            ],
            'manager': [
                Permission.VIEW_USERS, Permission.VIEW_REPORTS
            ],
            'user': [],
            'guest': []
        }
    
    def _get_safe_connection(self):
        """Obtém conexão segura com tratamento de transações"""
        try:
            conn = self.db_manager.get_connection()
            # Verificar se conexão está válida
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            return conn
        except Exception as e:
            self.logger.error(f"Database connection error: {e}")
            # Tentar nova conexão
            try:
                return self.db_manager.get_connection()
            except:
                return None
    
    def _safe_rollback(self, conn):
        """Rollback seguro da transação"""
        try:
            conn.rollback()
        except Exception as e:
            self.logger.debug(f"Rollback error: {e}")
    
    def init_user_tables(self):
        """Inicializa tabelas estendidas de usuários se não existirem"""
        conn = None
        try:
            conn = self._get_safe_connection()
            if not conn:
                self.logger.error("Cannot initialize tables - no database connection")
                return
                
            cursor = conn.cursor()
            
            # Criar tabela de logs administrativos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin_logs (
                    id SERIAL PRIMARY KEY,
                    admin_username VARCHAR(50) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    target_username VARCHAR(50),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    details JSONB,
                    success BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Criar índices para logs
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_logs_timestamp ON admin_logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_logs_admin ON admin_logs(admin_username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action)")
            
            conn.commit()
            cursor.close()
            
            self.logger.info("✅ User management tables initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing user tables: {e}")
            if conn:
                self._safe_rollback(conn)
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def has_permission(self, username: str, permission: Permission) -> bool:
        """Verifica se usuário tem permissão específica"""
        try:
            user_role = self.get_user_role(username)
            if not user_role:
                return False
            
            role_perms = self.role_permissions.get(user_role, [])
            return permission in role_perms
            
        except Exception as e:
            self.logger.error(f"Error checking permission: {e}")
            return False
    
    def get_user_role(self, username: str) -> Optional[str]:
        """Obtém role do usuário"""
        conn = None
        try:
            conn = self._get_safe_connection()
            if not conn:
                return None
                
            cursor = conn.cursor()
            
            # Tentar tabela estendida primeiro
            try:
                cursor.execute("SELECT role FROM users_extended WHERE username = %s AND is_active = TRUE", (username,))
                result = cursor.fetchone()
                if result:
                    cursor.close()
                    return result[0]
            except:
                pass
            
            # Fallback: verificar se é admin por username
            if 'admin' in username.lower():
                cursor.close()
                return 'admin'
            
            cursor.close()
            return 'user'  # Role padrão
            
        except Exception as e:
            self.logger.error(f"Error getting user role: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def get_all_users(self, admin_username: str) -> List[Dict]:
        """Lista todos os usuários (requer permissão VIEW_USERS)"""
        conn = None
        try:
            if not self.has_permission(admin_username, Permission.VIEW_USERS):
                self.logger.warning(f"User {admin_username} attempted to view users without permission")
                return []
            
            conn = self._get_safe_connection()
            if not conn:
                return []
                
            cursor = conn.cursor()
            users = []
            
            # Tentar tabela estendida primeiro
            try:
                cursor.execute("""
                    SELECT username, full_name, email, phone, department, role, status,
                           mfa_enabled, created_at, updated_at, last_login, notes
                    FROM users_extended
                    WHERE is_active = TRUE
                    ORDER BY created_at DESC
                """)
                
                results = cursor.fetchall()
                
                for row in results:
                    users.append({
                        'username': row[0],
                        'full_name': row[1],
                        'email': row[2],
                        'phone': row[3],
                        'department': row[4],
                        'role': row[5] or 'user',
                        'status': row[6] or 'active',
                        'mfa_enabled': row[7] or False,
                        'created_at': row[8],
                        'updated_at': row[9],
                        'last_login': row[10],
                        'notes': row[11]
                    })
                    
            except Exception as extended_error:
                self.logger.debug(f"Extended table not available: {extended_error}")
                
                # Fallback para tabela básica
                cursor.execute("""
                    SELECT username, email, mfa_enabled, created_at
                    FROM users
                    WHERE is_active = TRUE
                    ORDER BY created_at DESC
                """)
                
                results = cursor.fetchall()
                
                for row in results:
                    users.append({
                        'username': row[0],
                        'full_name': row[0],  # Usar username como fallback
                        'email': row[1],
                        'phone': None,
                        'department': None,
                        'role': 'admin' if 'admin' in row[0].lower() else 'user',
                        'status': 'active',
                        'mfa_enabled': row[2] or False,
                        'created_at': row[3],
                        'updated_at': None,
                        'last_login': None,
                        'notes': None
                    })
            
            cursor.close()
            self.logger.info(f"Admin {admin_username} retrieved {len(users)} users")
            return users
            
        except Exception as e:
            self.logger.error(f"Error getting all users: {e}")
            return []
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def create_user(self, admin_username: str, user_data: Dict) -> Tuple[bool, str]:
        """Cria novo usuário (requer permissão CREATE_USERS)"""
        conn = None
        try:
            if not self.has_permission(admin_username, Permission.CREATE_USERS):
                return False, "Sem permissão para criar usuários"
            
            # Validar dados obrigatórios
            required_fields = ['username', 'password', 'full_name']
            for field in required_fields:
                if not user_data.get(field):
                    return False, f"Campo obrigatório: {field}"
            
            # Verificar se usuário já existe
            if self._user_exists(user_data['username']):
                return False, f"Usuário {user_data['username']} já existe"
            
            conn = self._get_safe_connection()
            if not conn:
                return False, "Erro de conexão com banco de dados"
                
            cursor = conn.cursor()
            
            # Hash da senha
            password_hash = hashlib.sha256(user_data['password'].encode()).hexdigest()
            
            # Criar na tabela users (básica)
            cursor.execute("""
                INSERT INTO users (username, password_hash, email, is_active, mfa_enabled, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                user_data['username'],
                password_hash,
                user_data.get('email'),
                True,
                False,
                datetime.now()
            ))
            
            # Criar na tabela users_extended (se disponível)
            try:
                cursor.execute("""
                    INSERT INTO users_extended 
                    (username, password_hash, email, full_name, phone, department, 
                     role, status, is_active, created_at, created_by, notes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user_data['username'],
                    password_hash,
                    user_data.get('email'),
                    user_data['full_name'],
                    user_data.get('phone'),
                    user_data.get('department'),
                    user_data.get('role', 'user'),
                    user_data.get('status', 'active'),
                    True,
                    datetime.now(),
                    admin_username,
                    user_data.get('notes')
                ))
            except Exception as extended_error:
                self.logger.debug(f"Could not create in extended table: {extended_error}")
            
            conn.commit()
            cursor.close()
            
            # Log da ação
            self._log_admin_action(
                admin_username,
                "CREATE_USER",
                user_data['username'],
                {"role": user_data.get('role', 'user')}
            )
            
            self.logger.info(f"User {user_data['username']} created by {admin_username}")
            return True, f"Usuário {user_data['username']} criado com sucesso"
            
        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            if conn:
                self._safe_rollback(conn)
            return False, f"Erro ao criar usuário: {str(e)}"
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def update_user(self, admin_username: str, target_username: str, updates: Dict) -> Tuple[bool, str]:
        """Atualiza dados do usuário (requer permissão UPDATE_USERS)"""
        conn = None
        try:
            if not self.has_permission(admin_username, Permission.UPDATE_USERS):
                return False, "Sem permissão para atualizar usuários"
            
            if not updates:
                return False, "Nenhuma atualização fornecida"
            
            conn = self._get_safe_connection()
            if not conn:
                return False, "Erro de conexão com banco de dados"
                
            cursor = conn.cursor()
            
            # Construir query de update dinamicamente
            set_clauses = []
            values = []
            
            # Campos permitidos para atualização
            allowed_fields = {
                'full_name', 'email', 'phone', 'department', 'role', 'status', 'notes'
            }
            
            for field, value in updates.items():
                if field in allowed_fields:
                    set_clauses.append(f"{field} = %s")
                    values.append(value)
            
            if not set_clauses:
                return False, "Nenhum campo válido para atualização"
            
            # Adicionar timestamp de atualização
            set_clauses.append("updated_at = %s")
            values.append(datetime.now())
            
            # Adicionar username para WHERE
            values.append(target_username)
            
            # Tentar atualizar tabela estendida primeiro
            updated = False
            try:
                query = f"""
                    UPDATE users_extended 
                    SET {', '.join(set_clauses)}
                    WHERE username = %s AND is_active = TRUE
                """
                
                cursor.execute(query, values)
                updated = cursor.rowcount > 0
                    
            except Exception as extended_error:
                self.logger.debug(f"Extended table update failed: {extended_error}")
                
                # Fallback para campos básicos na tabela users
                basic_updates = {k: v for k, v in updates.items() if k in ['email']}
                
                if basic_updates:
                    basic_set = []
                    basic_values = []
                    
                    for field, value in basic_updates.items():
                        basic_set.append(f"{field} = %s")
                        basic_values.append(value)
                    
                    basic_values.append(target_username)
                    
                    cursor.execute(f"""
                        UPDATE users 
                        SET {', '.join(basic_set)}
                        WHERE username = %s AND is_active = TRUE
                    """, basic_values)
                    
                    updated = cursor.rowcount > 0
            
            if not updated:
                return False, f"Usuário {target_username} não encontrado"
            
            conn.commit()
            cursor.close()
            
            # Log da ação
            self._log_admin_action(
                admin_username,
                "UPDATE_USER",
                target_username,
                updates
            )
            
            self.logger.info(f"User {target_username} updated by {admin_username}")
            return True, f"Usuário {target_username} atualizado com sucesso"
            
        except Exception as e:
            self.logger.error(f"Error updating user: {e}")
            if conn:
                self._safe_rollback(conn)
            return False, f"Erro ao atualizar usuário: {str(e)}"
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def delete_user(self, admin_username: str, target_username: str, 
                   delete_type: str = "hard", delete_files: bool = True) -> Tuple[bool, str]:
        """
        Deleta usuário com opções de soft delete ou hard delete - CORRIGIDO PARA FOREIGN KEYS
        
        Args:
            admin_username: Admin executando a ação
            target_username: Usuário a ser deletado
            delete_type: "soft" (desativar) ou "hard" (remover do banco)
            delete_files: Se deve deletar arquivos do usuário no S3
        """
        conn = None
        try:
            if not self.has_permission(admin_username, Permission.DELETE_USERS):
                return False, "Sem permissão para deletar usuários"
            
            if admin_username == target_username:
                return False, "Não é possível deletar a si mesmo"
            
            # Verificar se usuário existe
            if not self._user_exists_any(target_username):
                return False, f"Usuário {target_username} não encontrado"
            
            conn = self._get_safe_connection()
            if not conn:
                return False, "Erro de conexão com banco de dados"
                
            cursor = conn.cursor()
            
            # Executar tipo de deleção escolhido
            if delete_type == "hard":
                # Hard delete - remove fisicamente do banco COM ORDEM CORRETA
                deleted, related_count, files_deleted = self._hard_delete_user_fixed(target_username, cursor, delete_files)
                action_type = "HARD_DELETE_USER"
                success_msg = f"Usuário {target_username} removido permanentemente do banco"
            else:
                # Soft delete - marca como inativo (comportamento original)
                deleted, related_count = self._soft_delete_user(target_username, cursor)
                files_deleted = 0
                if delete_files and self.s3_manager:
                    files_deleted = self._delete_user_files_s3_only(target_username, cursor)
                action_type = "SOFT_DELETE_USER"
                success_msg = f"Usuário {target_username} desativado"
            
            if not deleted:
                return False, f"Erro ao deletar usuário {target_username}"
            
            conn.commit()
            cursor.close()
            
            # Log da ação
            self._log_admin_action(
                admin_username,
                action_type,
                target_username,
                {
                    "delete_type": delete_type,
                    "files_deleted": files_deleted,
                    "related_records": related_count,
                    "delete_files": delete_files
                }
            )
            
            detailed_msg = f"{success_msg}. Arquivos: {files_deleted}, Registros relacionados: {related_count}"
            self.logger.info(f"User deletion completed: {detailed_msg}")
            return True, detailed_msg
            
        except Exception as e:
            self.logger.error(f"Error deleting user: {e}")
            if conn:
                self._safe_rollback(conn)
            return False, f"Erro ao deletar usuário: {str(e)}"
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def _hard_delete_user_fixed(self, target_username: str, cursor, delete_files: bool = True) -> Tuple[bool, int, int]:
        """
        Hard delete CORRIGIDO - remove usuário fisicamente respeitando foreign keys
        ORDEM CORRETA: primeiro arquivos, depois logs, depois usuário
        """
        try:
            related_count = 0
            files_deleted = 0
            
            # PASSO 1: Deletar arquivos PRIMEIRO (resolve foreign key constraint)
            if delete_files and self.s3_manager:
                files_deleted = self._delete_user_files_complete(target_username, cursor)
                self.logger.info(f"Deleted {files_deleted} files for user {target_username}")
            else:
                # Se não quer deletar do S3, pelo menos remove os registros do banco
                cursor.execute("DELETE FROM files WHERE uploaded_by = %s", (target_username,))
                files_deleted = cursor.rowcount
                self.logger.info(f"Removed {files_deleted} file records from database")
            
            # PASSO 2: Deletar dados relacionados (em ordem segura)
            related_tables_ordered = [
                # Primeiro: tabelas que referenciam o usuário como foreign key
                ("downloads", "downloaded_by"),
                ("temporary_links", "created_by"),
                ("user_sessions", "username"),
                # Logs por último (podem não ter constraint)
                ("admin_logs", "admin_username"),
                ("admin_logs", "target_username"),
            ]
            
            for table, column in related_tables_ordered:
                try:
                    cursor.execute(f"DELETE FROM {table} WHERE {column} = %s", (target_username,))
                    deleted_rows = cursor.rowcount
                    related_count += deleted_rows
                    if deleted_rows > 0:
                        self.logger.debug(f"Deleted {deleted_rows} records from {table}.{column}")
                except Exception as e:
                    self.logger.debug(f"Could not delete from {table}.{column}: {e}")
            
            # PASSO 3: Deletar de users_extended (se existir)
            try:
                cursor.execute("DELETE FROM users_extended WHERE username = %s", (target_username,))
                if cursor.rowcount > 0:
                    self.logger.debug(f"Hard deleted from users_extended: {target_username}")
            except Exception as e:
                self.logger.debug(f"Extended table hard delete failed: {e}")
            
            # PASSO 4: Deletar de users (tabela principal) - POR ÚLTIMO
            cursor.execute("DELETE FROM users WHERE username = %s", (target_username,))
            deleted = cursor.rowcount > 0
            
            if deleted:
                self.logger.info(f"Hard delete completed for user: {target_username} (files: {files_deleted}, related: {related_count})")
            
            return deleted, related_count, files_deleted
            
        except Exception as e:
            self.logger.error(f"Hard delete error: {e}")
            return False, 0, 0
    
    def _delete_user_files_complete(self, username: str, cursor) -> int:
        """Deleta arquivos do S3 E registros do banco (para hard delete)"""
        try:
            # Obter lista de arquivos do usuário
            cursor.execute("SELECT file_key FROM files WHERE uploaded_by = %s", (username,))
            file_keys = [row[0] for row in cursor.fetchall()]
            
            # Deletar arquivos do S3
            deleted_count = 0
            for file_key in file_keys:
                try:
                    if self.s3_manager.delete_file(file_key):
                        deleted_count += 1
                        self.logger.debug(f"Deleted S3 file: {file_key}")
                except Exception as e:
                    self.logger.warning(f"Failed to delete S3 file {file_key}: {e}")
            
            # Deletar registros de arquivos do banco
            cursor.execute("DELETE FROM files WHERE uploaded_by = %s", (username,))
            db_deleted = cursor.rowcount
            
            self.logger.info(f"Deleted {deleted_count} S3 files and {db_deleted} DB records for user {username}")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Error deleting user files complete: {e}")
            return 0
    
    def _delete_user_files_s3_only(self, username: str, cursor) -> int:
        """Deleta apenas arquivos do S3 (para soft delete, mantém registros no banco)"""
        try:
            # Obter lista de arquivos do usuário
            cursor.execute("SELECT file_key FROM files WHERE uploaded_by = %s", (username,))
            file_keys = [row[0] for row in cursor.fetchall()]
            
            # Deletar apenas do S3
            deleted_count = 0
            for file_key in file_keys:
                try:
                    if self.s3_manager.delete_file(file_key):
                        deleted_count += 1
                        self.logger.debug(f"Deleted S3 file: {file_key}")
                except Exception as e:
                    self.logger.warning(f"Failed to delete S3 file {file_key}: {e}")
            
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Error deleting user files S3 only: {e}")
            return 0
    
    def _soft_delete_user(self, target_username: str, cursor) -> Tuple[bool, int]:
        """Soft delete - marca usuário como inativo (comportamento original)"""
        try:
            related_count = 0
            
            # Soft delete em users_extended
            try:
                cursor.execute("""
                    UPDATE users_extended 
                    SET is_active = FALSE, updated_at = %s, status = 'deleted'
                    WHERE username = %s
                """, (datetime.now(), target_username))
                
                if cursor.rowcount > 0:
                    self.logger.debug(f"Soft deleted from users_extended: {target_username}")
            except Exception as e:
                self.logger.debug(f"Extended table soft delete failed: {e}")
            
            # Soft delete em users (tabela principal)
            cursor.execute("""
                UPDATE users 
                SET is_active = FALSE
                WHERE username = %s
            """, (target_username,))
            
            deleted = cursor.rowcount > 0
            
            if deleted:
                self.logger.info(f"Soft delete completed for user: {target_username}")
            
            return deleted, related_count
            
        except Exception as e:
            self.logger.error(f"Soft delete error: {e}")
            return False, 0
    
    def search_users(self, admin_username: str, query: str, filters: Dict = None) -> List[Dict]:
        """Busca usuários com filtros"""
        try:
            if not self.has_permission(admin_username, Permission.VIEW_USERS):
                return []
            
            all_users = self.get_all_users(admin_username)
            
            if not query and not filters:
                return all_users
            
            filtered_users = all_users
            
            # Filtrar por query de texto
            if query:
                query_lower = query.lower()
                filtered_users = [
                    user for user in filtered_users
                    if (query_lower in user['username'].lower() or
                        query_lower in (user.get('full_name') or '').lower() or
                        query_lower in (user.get('email') or '').lower() or
                        query_lower in (user.get('department') or '').lower())
                ]
            
            # Aplicar filtros adicionais
            if filters:
                for field, value in filters.items():
                    if value is not None:
                        filtered_users = [
                            user for user in filtered_users
                            if user.get(field) == value
                        ]
            
            return filtered_users
            
        except Exception as e:
            self.logger.error(f"Error searching users: {e}")
            return []
    
    def get_user_statistics(self, admin_username: str) -> Dict:
        """Obtém estatísticas de usuários"""
        conn = None
        try:
            if not self.has_permission(admin_username, Permission.VIEW_USERS):
                return {}
            
            conn = self._get_safe_connection()
            if not conn:
                return {}
                
            cursor = conn.cursor()
            stats = {}
            
            # Estatísticas básicas
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
            stats['total_users'] = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE AND mfa_enabled = TRUE")
            stats['mfa_users'] = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE AND created_at >= NOW() - INTERVAL '30 days'")
            stats['recent_users'] = cursor.fetchone()[0] or 0
            
            # Estatísticas por status (se tabela estendida disponível)
            try:
                cursor.execute("""
                    SELECT status, COUNT(*) 
                    FROM users_extended 
                    WHERE is_active = TRUE 
                    GROUP BY status
                """)
                
                status_counts = dict(cursor.fetchall())
                stats['status_counts'] = status_counts
                stats['active_users'] = status_counts.get('active', 0)
                
            except:
                stats['active_users'] = stats['total_users']
                stats['status_counts'] = {'active': stats['total_users']}
            
            # Estatísticas por role (se tabela estendida disponível)
            try:
                cursor.execute("""
                    SELECT role, COUNT(*) 
                    FROM users_extended 
                    WHERE is_active = TRUE 
                    GROUP BY role
                """)
                
                stats['role_counts'] = dict(cursor.fetchall())
                
            except:
                stats['role_counts'] = {'user': stats['total_users']}
            
            cursor.close()
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting user statistics: {e}")
            return {}
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def _user_exists(self, username: str) -> bool:
        """Verifica se usuário ativo já existe"""
        conn = None
        try:
            conn = self._get_safe_connection()
            if not conn:
                return True  # Ser conservador
                
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s AND is_active = TRUE", (username,))
            exists = cursor.fetchone()[0] > 0
            
            cursor.close()
            return exists
            
        except Exception as e:
            self.logger.error(f"Error checking if user exists: {e}")
            return True  # Ser conservador em caso de erro
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def _user_exists_any(self, username: str) -> bool:
        """Verifica se usuário existe (ativo ou inativo)"""
        conn = None
        try:
            conn = self._get_safe_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
            exists = cursor.fetchone()[0] > 0
            
            cursor.close()
            return exists
            
        except Exception as e:
            self.logger.error(f"Error checking if user exists (any): {e}")
            return False
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def _log_admin_action(self, admin_username: str, action: str, target_username: str = None, details: Dict = None):
        """Log de ações administrativas"""
        conn = None
        try:
            conn = self._get_safe_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO admin_logs (admin_username, action, target_username, details, timestamp, success)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                admin_username,
                action,
                target_username,
                json.dumps(details) if details else None,
                datetime.now(),
                True
            ))
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            self.logger.error(f"Error logging admin action: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass

# Funções auxiliares mantidas
import streamlit as st
import pandas as pd

def setup_logger():
    """Configura logger de forma robusta"""
    logger = logging.getLogger('user_management')
    
    if logger.handlers:
        return logger
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    return logger

def is_admin_user(username: str) -> bool:
    """Verificação de admin - FLEXÍVEL PARA TESTES"""
    
    # Lista de usernames admin conhecidos
    admin_usernames = [
        'admin', 'administrator', 'root', 'adm', 'administrador',
        'admin1', 'admin123', 'sa', 'sysadmin', 'superuser'
    ]
    
    # Verificação principal
    username_lower = username.lower()
    
    # Método 1: Username específico ou contém admin
    if username_lower in admin_usernames or 'admin' in username_lower:
        return True
    
    # Método 2: Verificar no banco se possível
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Tentar tabela estendida primeiro
        try:
            cursor.execute("SELECT role FROM users_extended WHERE username = %s", (username,))
            result = cursor.fetchone()
            if result and result[0] in ['admin', 'super_admin']:
                cursor.close()
                conn.close()
                return True
        except:
            pass
        
        # Verificar se é o único usuário (primeiro usuário é admin)
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        user_count = cursor.fetchone()[0]
        
        if user_count == 1:
            cursor.close()
            conn.close()
            return True
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.debug(f"Erro ao verificar admin no banco: {e}")
    
    return False

# Inicializar logger
logger = setup_logger()
logger.info("✅ User management system with FIXED HARD DELETE (foreign key safe) loaded successfully")
