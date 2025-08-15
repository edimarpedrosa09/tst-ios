"""
Sistema Administrativo Completo - admin_pages.py - VERSÃO CORRIGIDA FINAL
Corrige TODAS as chamadas de deleção para usar hard delete por padrão
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import hashlib
import secrets
import string

# CONFIGURAÇÃO ROBUSTA DO LOGGER
import logging
import sys

def setup_logger():
    """Configura logger de forma robusta"""
    logger = logging.getLogger('admin_pages')
    
    if logger.handlers:
        return logger
    
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    return logger

# Criar logger global
logger = setup_logger()

def render_admin_panel(username: str, user_manager=None):
    """Painel administrativo principal com verificação de permissões CORRIGIDA"""
    
    # VERIFICAÇÃO DE PERMISSÕES ROBUSTA E CORRIGIDA
    is_admin = check_admin_permissions_comprehensive(username, user_manager)
    
    if not is_admin:
        st.error("❌ Acesso negado. Apenas administradores podem acessar esta seção.")
        st.info(f"💡 Username atual: '{username}' - Para ser admin, seu username deve conter 'admin'")
        
        # Informações de debug detalhadas
        with st.expander("🔍 Debug - Verificação de Permissões Detalhada"):
            debug_admin_permissions(username, user_manager)
        return
    
    st.header("🛡️ Painel Administrativo")
    st.success(f"✅ Acesso liberado para: {username}")
    
    # Sidebar de navegação administrativa
    with st.sidebar:
        st.markdown("---")
        st.subheader("🛡️ Admin")
        
        admin_page = st.selectbox(
            "Seção:",
            ["dashboard", "users", "files", "reports", "advanced_reports", "user_management", "system_logs"],
            format_func=lambda x: {
                "dashboard": "📊 Dashboard",
                "users": "👥 Usuários",
                "files": "📁 Arquivos",
                "reports": "📈 Relatórios Básicos",
                "advanced_reports": "📊 Relatórios Avançados",
                "user_management": "👤 Gerenciar Usuários",
                "system_logs": "📋 Logs do Sistema"
            }[x],
            key="admin_nav_select"
        )
        
        st.session_state.admin_current_page = admin_page
        
        # Info do admin com status de permissões
        st.markdown("---")
        st.caption(f"👤 {username}")
        st.caption(f"🛡️ Admin: {'✅' if is_admin else '❌'}")
        st.caption(f"🕒 {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    
    # Renderizar página selecionada
    try:
        page = st.session_state.get('admin_current_page', 'dashboard')
        
        if page == 'dashboard':
            render_admin_dashboard()
        elif page == 'users':
            render_admin_users()
        elif page == 'files':
            render_admin_files()
        elif page == 'reports':
            render_reports_section(username, user_manager)
        elif page == 'advanced_reports':
            render_advanced_reports_section(username, user_manager)
        elif page == 'user_management':
            # PASSAR is_admin EXPLICITAMENTE
            render_user_management_section(username, user_manager, is_admin)
        elif page == 'system_logs':
            render_system_logs_section()
            
    except Exception as e:
        st.error(f"❌ Erro ao carregar seção: {e}")
        logger.error(f"Admin section error: {e}")

def check_admin_permissions_comprehensive(username: str, user_manager=None) -> bool:
    """
    Verificação COMPREHENSIVE de permissões administrativas
    Usa múltiplos métodos para garantir que o admin seja reconhecido
    """
    logger.info(f"🔍 Checking admin permissions for: {username}")
    
    # MÉTODO 1: Verificação por username (mais básica e confiável)
    if is_admin_by_username(username):
        logger.info(f"✅ Admin confirmed by username: {username}")
        return True
    
    # MÉTODO 2: Verificação via user_manager se disponível
    if user_manager:
        try:
            # Verificar se tem método has_permission
            if hasattr(user_manager, 'has_permission'):
                from user_management import Permission
                if user_manager.has_permission(username, Permission.DELETE_USERS):
                    logger.info(f"✅ Admin confirmed by user_manager permissions: {username}")
                    return True
            
            # Verificar role diretamente
            if hasattr(user_manager, 'get_user_role'):
                role = user_manager.get_user_role(username)
                if role in ['admin', 'super_admin']:
                    logger.info(f"✅ Admin confirmed by role: {username} -> {role}")
                    return True
        except Exception as e:
            logger.warning(f"User manager check failed: {e}")
    
    # MÉTODO 3: Verificação direta no banco de dados
    try:
        admin_by_db = check_admin_in_database(username)
        if admin_by_db:
            logger.info(f"✅ Admin confirmed by database: {username}")
            return True
    except Exception as e:
        logger.warning(f"Database check failed: {e}")
    
    # MÉTODO 4: Verificação se é o primeiro/único usuário
    try:
        if is_first_user(username):
            logger.info(f"✅ Admin confirmed as first user: {username}")
            return True
    except Exception as e:
        logger.warning(f"First user check failed: {e}")
    
    logger.warning(f"❌ Admin permissions DENIED for: {username}")
    return False

def is_admin_by_username(username: str) -> bool:
    """Verificação por username - método mais básico e confiável"""
    admin_usernames = [
        'admin', 'administrator', 'root', 'adm', 'administrador',
        'admin1', 'admin123', 'sa', 'sysadmin', 'superuser', 'administrator'
    ]
    
    username_lower = username.lower()
    
    # Verificação exata
    if username_lower in admin_usernames:
        return True
    
    # Verificação se contém 'admin'
    if 'admin' in username_lower:
        return True
    
    # Verificação se contém 'root'
    if 'root' in username_lower:
        return True
    
    return False

def check_admin_in_database(username: str) -> bool:
    """Verificação direta no banco de dados"""
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
            if result:
                role = result[0]
                cursor.close()
                conn.close()
                return role in ['admin', 'super_admin', 'administrator']
        except Exception as e:
            logger.debug(f"Extended table check failed: {e}")
        
        # Verificar tabela básica
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s AND is_active = TRUE", (username,))
        user_exists = cursor.fetchone()[0] > 0
        
        cursor.close()
        conn.close()
        
        # Se usuário existe e username indica admin, considerar admin
        if user_exists and is_admin_by_username(username):
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"Database admin check error: {e}")
        return False

def is_first_user(username: str) -> bool:
    """Verifica se é o primeiro/único usuário (que deve ser admin)"""
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT username FROM users WHERE is_active = TRUE ORDER BY created_at LIMIT 1")
        first_user = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        # Se há apenas 1 usuário ou se é o primeiro usuário criado
        if total_users == 1 or (first_user and first_user[0] == username):
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"First user check error: {e}")
        return False

def debug_admin_permissions(username: str, user_manager=None):
    """Debug detalhado das verificações de permissão"""
    st.write("**🔍 Verificação Detalhada de Permissões:**")
    
    # Teste 1: Username
    username_check = is_admin_by_username(username)
    st.write(f"1. **Username check**: {'✅' if username_check else '❌'}")
    st.write(f"   - Username: '{username}'")
    st.write(f"   - Contém 'admin': {'admin' in username.lower()}")
    st.write(f"   - Contém 'root': {'root' in username.lower()}")
    
    # Teste 2: User Manager
    user_manager_check = False
    if user_manager:
        try:
            if hasattr(user_manager, 'get_user_role'):
                role = user_manager.get_user_role(username)
                user_manager_check = role in ['admin', 'super_admin']
                st.write(f"2. **User Manager check**: {'✅' if user_manager_check else '❌'}")
                st.write(f"   - Role detectado: {role}")
            else:
                st.write("2. **User Manager check**: ⚠️ Método get_user_role não disponível")
        except Exception as e:
            st.write(f"2. **User Manager check**: ❌ Erro: {e}")
    else:
        st.write("2. **User Manager check**: ⚠️ User manager não disponível")
    
    # Teste 3: Database
    try:
        db_check = check_admin_in_database(username)
        st.write(f"3. **Database check**: {'✅' if db_check else '❌'}")
    except Exception as e:
        st.write(f"3. **Database check**: ❌ Erro: {e}")
    
    # Teste 4: First User
    try:
        first_user_check = is_first_user(username)
        st.write(f"4. **First user check**: {'✅' if first_user_check else '❌'}")
    except Exception as e:
        st.write(f"4. **First user check**: ❌ Erro: {e}")
    
    # Resultado final
    final_result = check_admin_permissions_comprehensive(username, user_manager)
    st.write(f"**🎯 Resultado Final**: {'✅ ADMIN' if final_result else '❌ NOT ADMIN'}")
    
    # Sugestões
    if not final_result:
        st.write("**💡 Para obter acesso admin:**")
        st.write("- Crie um usuário com username que contenha 'admin' (ex: 'admin', 'myadmin', 'admin123')")
        st.write("- Ou configure o role='admin' na tabela users_extended")
        st.write("- Ou seja o primeiro usuário do sistema")

def render_user_management_section(username: str, user_manager=None, is_admin=False):
    """Renderiza seção COMPLETA de gerenciamento de usuários - COM PERMISSÕES CORRIGIDAS"""
    
    st.subheader("👤 Gerenciamento Completo de Usuários")
    
    # Verificar se user_manager está disponível
    if not user_manager:
        st.error("❌ Sistema de gerenciamento de usuários não disponível")
        return
    
    # VERIFICAÇÃO DE PERMISSÕES CORRIGIDA - usar is_admin passado como parâmetro
    if not is_admin:
        st.error("❌ Sem permissão para gerenciar usuários")
        st.info("💡 Apenas administradores podem acessar esta seção")
        return
    
    # Tabs do gerenciamento
    tab1, tab2, tab3, tab4 = st.tabs([
        "👥 Lista de Usuários",
        "➕ Criar Usuário", 
        "🔍 Buscar Usuários",
        "📊 Estatísticas"
    ])
    
    with tab1:
        render_users_list_no_forms(username, user_manager, is_admin)
    
    with tab2:
        render_create_user_no_forms(username, user_manager, is_admin)
    
    with tab3:
        render_user_search_no_forms(username, user_manager, is_admin)
    
    with tab4:
        render_user_statistics_no_forms(username, user_manager, is_admin)

def render_users_list_no_forms(admin_username: str, user_manager, is_admin=False):
    """Renderiza lista de usuários SEM formulários aninhados - COM HARD DELETE"""
    
    st.write("### 👥 Lista de Usuários")
    
    try:
        users = user_manager.get_all_users(admin_username)
        
        if not users:
            st.info("📋 Nenhum usuário encontrado")
            return
        
        st.write(f"📊 **Total de usuários:** {len(users)}")
        
        # Filtros em colunas separadas - SEM FORMULÁRIO
        col1, col2, col3 = st.columns(3)
        
        with col1:
            filter_role = st.selectbox(
                "Filtrar por Role:",
                ["Todos", "super_admin", "admin", "manager", "user", "guest"],
                key="filter_role_list"
            )
        
        with col2:
            filter_status = st.selectbox(
                "Filtrar por Status:",
                ["Todos", "active", "inactive", "pending", "suspended"],
                key="filter_status_list"
            )
        
        with col3:
            search_term = st.text_input(
                "Buscar usuário:",
                placeholder="nome ou username...",
                key="search_users_term"
            )
        
        # Aplicar filtros
        filtered_users = users.copy()
        
        if filter_role != "Todos":
            filtered_users = [u for u in filtered_users if u.get('role') == filter_role]
        
        if filter_status != "Todos":
            filtered_users = [u for u in filtered_users if u.get('status') == filter_status]
        
        if search_term:
            search_lower = search_term.lower()
            filtered_users = [
                u for u in filtered_users 
                if search_lower in u['username'].lower() 
                or search_lower in (u.get('full_name') or '').lower()
            ]
        
        st.write(f"📋 **Exibindo:** {len(filtered_users)} usuários")
        
        # Lista de usuários - SEM FORMULÁRIOS
        for idx, user in enumerate(filtered_users):
            render_user_card_with_hard_delete(user, idx, admin_username, user_manager, is_admin)
            
    except Exception as e:
        st.error(f"❌ Erro ao carregar usuários: {e}")
        logger.error(f"Error loading users: {e}")

def render_user_card_with_hard_delete(user: Dict, idx: int, admin_username: str, user_manager, is_admin=False):
    """Renderiza card individual de usuário - COM HARD DELETE CORRIGIDO"""
    
    with st.container():
        col1, col2, col3, col4 = st.columns([3, 1, 1, 2])
        
        with col1:
            # Informações principais
            admin_badge = " 🛡️" if user.get('role') in ['admin', 'super_admin'] else ""
            st.write(f"**👤 {user.get('full_name') or user['username']}{admin_badge}**")
            st.caption(f"@{user['username']} • {user.get('email') or 'Sem email'}")
            
            if user.get('department'):
                st.caption(f"🏢 {user['department']}")
        
        with col2:
            # Status e Role
            status_color = {
                'active': '🟢',
                'inactive': '🔴', 
                'pending': '🟡',
                'suspended': '🟠'
            }.get(user.get('status'), '⚪')
            
            st.write(f"{status_color} {user.get('status', 'active').title()}")
            st.caption(f"🎭 {user.get('role', 'user').replace('_', ' ').title()}")
        
        with col3:
            # MFA e Login
            mfa_icon = "🔐" if user.get('mfa_enabled') else "🔓"
            st.write(f"{mfa_icon} MFA")
            
            if user.get('last_login'):
                try:
                    last_login = user['last_login']
                    if isinstance(last_login, str):
                        last_login = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
                    st.caption(f"🕒 {last_login.strftime('%d/%m/%Y')}")
                except:
                    st.caption("🕒 Data inválida")
            else:
                st.caption("🕒 Nunca logou")
        
        with col4:
            # Ações - USANDO SESSION STATE PARA EVITAR FORMULÁRIOS - COM HARD DELETE
            if user['username'] != admin_username and is_admin:
                
                # Key único para este usuário
                user_key = user['username']
                
                # Botão principal de ações
                if st.button("⚙️ Ações", key=f"actions_btn_{user_key}_{idx}", use_container_width=True):
                    # Toggle do estado de ações
                    current_state = st.session_state.get(f"show_actions_{user_key}", False)
                    st.session_state[f"show_actions_{user_key}"] = not current_state
                    st.rerun()
                
                # Mostrar ações se ativadas
                if st.session_state.get(f"show_actions_{user_key}", False):
                    
                    # Container para ações
                    with st.container():
                        st.write("**Ações disponíveis:**")
                        
                        # Reset de senha
                        if st.button(f"🔑 Reset Senha", key=f"reset_{user_key}_{idx}", use_container_width=True):
                            new_password = _generate_temp_password()
                            success, message = _reset_user_password_simple(
                                admin_username, user['username'], new_password, user_manager
                            )
                            
                            if success:
                                st.success(f"✅ Senha resetada!")
                                st.info(f"🔑 Nova senha: `{new_password}`")
                                st.warning("⚠️ Anote esta senha!")
                                # Fechar ações após sucesso
                                st.session_state[f"show_actions_{user_key}"] = False
                                st.rerun()
                            else:
                                st.error(f"❌ {message}")
                        
                        # Toggle Status
                        new_status = 'inactive' if user.get('status') == 'active' else 'active'
                        status_action = 'Desativar' if user.get('status') == 'active' else 'Ativar'
                        
                        if st.button(f"🔄 {status_action}", key=f"toggle_{user_key}_{idx}", use_container_width=True):
                            success, message = user_manager.update_user(
                                admin_username, 
                                user['username'], 
                                {'status': new_status}
                            )
                            
                            if success:
                                st.success(f"✅ Status alterado!")
                                # Fechar ações após sucesso
                                st.session_state[f"show_actions_{user_key}"] = False
                                st.rerun()
                            else:
                                st.error(f"❌ {message}")
                        
                        # DELEÇÃO COM OPÇÕES - HARD DELETE POR PADRÃO
                        if not st.session_state.get(f"confirm_delete_{user_key}", False):
                            if st.button(f"🗑️ Deletar do Banco", key=f"delete_{user_key}_{idx}", type="secondary", use_container_width=True):
                                st.session_state[f"confirm_delete_{user_key}"] = True
                                st.rerun()
                        else:
                            st.warning("⚠️ **Deleção Permanente**")
                            st.write(f"Deletar usuário **{user['username']}** do banco?")
                            
                            # Opções de deleção
                            col_type1, col_type2 = st.columns(2)
                            
                            with col_type1:
                                if st.button("🗑️ Hard Delete", key=f"hard_del_{user_key}_{idx}", 
                                           help="Remove permanentemente do banco", use_container_width=True):
                                    # HARD DELETE - NOVA FUNÇÃO
                                    success, message = user_manager.delete_user(
                                        admin_username, 
                                        user['username'], 
                                        delete_type="hard",  # HARD DELETE
                                        delete_files=True    # Deletar arquivos também
                                    )
                                    
                                    if success:
                                        st.success(f"✅ {message}")
                                        # Limpar estados
                                        st.session_state[f"confirm_delete_{user_key}"] = False
                                        st.session_state[f"show_actions_{user_key}"] = False
                                        st.balloons()
                                        st.rerun()
                                    else:
                                        st.error(f"❌ {message}")
                            
                            with col_type2:
                                if st.button("📝 Soft Delete", key=f"soft_del_{user_key}_{idx}", 
                                           help="Apenas desativa (mantém no banco)", use_container_width=True):
                                    # SOFT DELETE - COMPORTAMENTO ORIGINAL
                                    success, message = user_manager.delete_user(
                                        admin_username, 
                                        user['username'], 
                                        delete_type="soft",   # SOFT DELETE
                                        delete_files=False    # Manter arquivos
                                    )
                                    
                                    if success:
                                        st.success(f"✅ {message}")
                                        # Limpar estados
                                        st.session_state[f"confirm_delete_{user_key}"] = False
                                        st.session_state[f"show_actions_{user_key}"] = False
                                        st.rerun()
                                    else:
                                        st.error(f"❌ {message}")
                            
                            # Cancelar
                            if st.button("❌ Cancelar", key=f"cancel_del_{user_key}_{idx}", use_container_width=True):
                                st.session_state[f"confirm_delete_{user_key}"] = False
                                st.rerun()
                        
                        # Editar usuário (modal simple)
                        if st.button(f"✏️ Editar", key=f"edit_{user_key}_{idx}", use_container_width=True):
                            st.session_state[f"editing_{user_key}"] = True
                            st.session_state[f"show_actions_{user_key}"] = False
                            st.rerun()
                        
                        # Fechar ações
                        if st.button("❌ Fechar", key=f"close_{user_key}_{idx}", use_container_width=True):
                            st.session_state[f"show_actions_{user_key}"] = False
                            st.rerun()
            
            elif user['username'] == admin_username:
                st.info("👤 Você")
            elif not is_admin:
                st.warning("🔒 Sem permissão")
        
        # Editor inline simples (fora do container principal)
        if st.session_state.get(f"editing_{user['username']}", False):
            render_simple_user_editor(user, admin_username, user_manager)
        
        st.divider()

def render_simple_user_editor(user: Dict, admin_username: str, user_manager):
    """Editor simples de usuário SEM FORMULÁRIOS ANINHADOS"""
    
    user_key = user['username']
    
    with st.container():
        st.write(f"✏️ **Editando: {user['username']}**")
        
        # Campos de edição em colunas
        col1, col2 = st.columns(2)
        
        with col1:
            new_full_name = st.text_input(
                "Nome Completo:", 
                value=user.get('full_name', ''),
                key=f"edit_name_{user_key}"
            )
            new_email = st.text_input(
                "Email:", 
                value=user.get('email', ''),
                key=f"edit_email_{user_key}"
            )
        
        with col2:
            new_department = st.text_input(
                "Departamento:", 
                value=user.get('department', ''),
                key=f"edit_dept_{user_key}"
            )
            
            current_role_idx = 0
            roles = ["user", "manager", "admin", "super_admin"]
            if user.get('role') in roles:
                current_role_idx = roles.index(user.get('role'))
            
            new_role = st.selectbox(
                "Role:", 
                roles,
                index=current_role_idx,
                key=f"edit_role_{user_key}"
            )
        
        # Botões de ação
        col_save, col_cancel = st.columns(2)
        
        with col_save:
            if st.button("💾 Salvar", key=f"save_{user_key}", use_container_width=True):
                # Preparar updates
                updates = {}
                
                if new_full_name != user.get('full_name', ''):
                    updates['full_name'] = new_full_name
                
                if new_email != user.get('email', ''):
                    updates['email'] = new_email
                
                if new_department != user.get('department', ''):
                    updates['department'] = new_department
                
                if new_role != user.get('role', 'user'):
                    updates['role'] = new_role
                
                if updates:
                    success, message = user_manager.update_user(
                        admin_username, user['username'], updates
                    )
                    
                    if success:
                        st.success(f"✅ {message}")
                        st.session_state[f"editing_{user_key}"] = False
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
                else:
                    st.info("ℹ️ Nenhuma alteração detectada")
        
        with col_cancel:
            if st.button("❌ Cancelar", key=f"cancel_{user_key}", use_container_width=True):
                st.session_state[f"editing_{user_key}"] = False
                st.rerun()

def render_create_user_no_forms(admin_username: str, user_manager, is_admin=False):
    """Renderiza criação de usuário SEM formulários aninhados - COM PERMISSÕES CORRIGIDAS"""
    
    st.write("### ➕ Criar Novo Usuário")
    
    if not is_admin:
        st.error("❌ Sem permissão para criar usuários")
        return
    
    # Usar session state para controlar o modo de criação
    if not st.session_state.get('creating_user', False):
        if st.button("➕ Iniciar Criação de Usuário", type="primary", use_container_width=True):
            st.session_state['creating_user'] = True
            st.rerun()
        return
    
    # Modo de criação ativo
    st.write("📝 **Preencha os dados do novo usuário**")
    
    # Campos em colunas
    col1, col2 = st.columns(2)
    
    with col1:
        username = st.text_input(
            "Usuário (login):", 
            placeholder="usuario.nome",
            key="create_username",
            help="Apenas letras, números, pontos e underscores"
        )
        
        full_name = st.text_input(
            "Nome Completo:", 
            placeholder="João Silva",
            key="create_fullname"
        )
        
        email = st.text_input(
            "Email:", 
            placeholder="joao.silva@empresa.com",
            key="create_email"
        )
    
    with col2:
        password = st.text_input(
            "Senha:", 
            type="password",
            key="create_password",
            help="Mínimo 8 caracteres"
        )
        
        department = st.text_input(
            "Departamento:", 
            placeholder="TI, RH, Financeiro...",
            key="create_department"
        )
        
        role = st.selectbox(
            "Role:",
            ["user", "manager", "admin", "super_admin"],
            index=0,
            key="create_role"
        )
    
    # Opções adicionais
    generate_password = st.checkbox(
        "🔑 Gerar senha automática (se campo senha vazio)",
        value=True,
        key="create_auto_password"
    )
    
    notes = st.text_area(
        "Observações:",
        placeholder="Informações adicionais...",
        key="create_notes"
    )
    
    # Botões de ação
    col_create, col_cancel = st.columns(2)
    
    with col_create:
        if st.button("👤 Criar Usuário", type="primary", use_container_width=True):
            # Validações
            errors = []
            
            if not username:
                errors.append("Username é obrigatório")
            elif len(username) < 3:
                errors.append("Username deve ter pelo menos 3 caracteres")
            
            if not full_name:
                errors.append("Nome completo é obrigatório")
            
            if email and '@' not in email:
                errors.append("Email inválido")
            
            # Gerar senha se necessário
            final_password = password
            if not password and generate_password:
                final_password = _generate_temp_password()
            
            if not final_password:
                errors.append("Senha é obrigatória")
            elif len(final_password) < 8:
                errors.append("Senha deve ter pelo menos 8 caracteres")
            
            if errors:
                for error in errors:
                    st.error(f"❌ {error}")
            else:
                # Criar usuário
                user_data = {
                    'username': username.lower().strip(),
                    'full_name': full_name.strip(),
                    'password': final_password,
                    'email': email.strip() if email else None,
                    'department': department.strip() if department else None,
                    'role': role,
                    'status': 'active',
                    'notes': notes.strip() if notes else None
                }
                
                success, message = user_manager.create_user(admin_username, user_data)
                
                if success:
                    st.success(f"✅ {message}")
                    
                    # Mostrar credenciais se geradas
                    if generate_password and not password:
                        st.info(f"🔑 **Senha gerada:** `{final_password}`")
                        st.warning("⚠️ Anote esta senha!")
                    
                    # Limpar estado
                    st.session_state['creating_user'] = False
                    st.balloons()
                    st.rerun()
                    
                else:
                    st.error(f"❌ {message}")
    
    with col_cancel:
        if st.button("❌ Cancelar", use_container_width=True):
            st.session_state['creating_user'] = False
            st.rerun()

def render_user_search_no_forms(admin_username: str, user_manager, is_admin=False):
    """Renderiza busca de usuários SEM formulários - COM PERMISSÕES CORRIGIDAS"""
    
    st.write("### 🔍 Busca Avançada de Usuários")
    
    if not is_admin:
        st.error("❌ Sem permissão para buscar usuários")
        return
    
    # Campos de busca
    col1, col2 = st.columns(2)
    
    with col1:
        search_query = st.text_input(
            "Termo de busca:",
            placeholder="nome, username, email...",
            key="search_query"
        )
        
        search_role = st.selectbox(
            "Filtrar por Role:",
            ["Todos", "user", "manager", "admin", "super_admin"],
            key="search_role"
        )
    
    with col2:
        search_status = st.selectbox(
            "Filtrar por Status:",
            ["Todos", "active", "inactive", "pending", "suspended"],
            key="search_status"
        )
        
        search_department = st.text_input(
            "Departamento:",
            placeholder="TI, RH...",
            key="search_department"
        )
    
    # Botão de busca
    if st.button("🔍 Buscar", type="primary", use_container_width=True):
        # Preparar filtros
        filters = {}
        
        if search_role != "Todos":
            filters['role'] = search_role
        
        if search_status != "Todos":
            filters['status'] = search_status
        
        if search_department:
            filters['department'] = search_department
        
        # Executar busca
        try:
            results = user_manager.search_users(admin_username, search_query, filters)
            
            if results:
                st.success(f"🔍 **{len(results)} usuários encontrados**")
                
                # Exibir resultados
                for idx, user in enumerate(results):
                    with st.container():
                        col1, col2, col3 = st.columns([4, 1, 1])
                        
                        with col1:
                            st.write(f"**👤 {user.get('full_name') or user['username']}**")
                            st.caption(f"@{user['username']} • {user.get('email', 'Sem email')}")
                            
                            if user.get('department'):
                                st.caption(f"🏢 {user['department']}")
                        
                        with col2:
                            st.write(f"🎭 {user.get('role', 'user').replace('_', ' ').title()}")
                            st.caption(f"📊 {user.get('status', 'active').title()}")
                        
                        with col3:
                            mfa_icon = "🔐" if user.get('mfa_enabled') else "🔓"
                            st.write(f"{mfa_icon} MFA")
                        
                        st.divider()
            
            else:
                st.info("🔍 Nenhum usuário encontrado")
        
        except Exception as e:
            st.error(f"❌ Erro na busca: {e}")

def render_user_statistics_no_forms(admin_username: str, user_manager, is_admin=False):
    """Renderiza estatísticas de usuários SEM formulários - COM PERMISSÕES CORRIGIDAS"""
    
    st.write("### 📊 Estatísticas de Usuários")
    
    if not is_admin:
        st.error("❌ Sem permissão para visualizar estatísticas")
        return
    
    try:
        stats = user_manager.get_user_statistics(admin_username)
        
        if not stats:
            st.info("📊 Sem dados estatísticos disponíveis")
            return
        
        # Métricas principais
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("👥 Total Usuários", f"{stats.get('total_users', 0):,}")
        
        with col2:
            st.metric("✅ Usuários Ativos", f"{stats.get('active_users', 0):,}")
        
        with col3:
            st.metric("🔐 Com MFA", f"{stats.get('mfa_users', 0):,}")
        
        with col4:
            st.metric("🆕 Novos (30d)", f"{stats.get('recent_users', 0):,}")
        
        # Gráficos usando métodos nativos do Streamlit
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("#### 📊 Distribuição por Status")
            status_counts = stats.get('status_counts', {})
            
            if status_counts:
                st.bar_chart(status_counts)
                
                # Tabela detalhada
                for status, count in status_counts.items():
                    percentage = (count / max(stats.get('total_users', 1), 1)) * 100
                    st.write(f"• **{status.title()}**: {count} ({percentage:.1f}%)")
            else:
                st.info("Sem dados de status")
        
        with col2:
            st.write("#### 🎭 Distribuição por Role")
            role_counts = stats.get('role_counts', {})
            
            if role_counts:
                st.bar_chart(role_counts)
                
                # Tabela detalhada
                for role, count in role_counts.items():
                    percentage = (count / max(stats.get('total_users', 1), 1)) * 100
                    display_role = role.replace('_', ' ').title()
                    st.write(f"• **{display_role}**: {count} ({percentage:.1f}%)")
            else:
                st.info("Sem dados de roles")
        
        # Análises
        st.markdown("---")
        st.write("#### 📈 Análises")
        
        total_users = stats.get('total_users', 0)
        active_users = stats.get('active_users', 0)
        mfa_users = stats.get('mfa_users', 0)
        
        if total_users > 0:
            activity_rate = (active_users / total_users) * 100
            mfa_rate = (mfa_users / total_users) * 100
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("📈 Taxa de Atividade", f"{activity_rate:.1f}%")
                
                if activity_rate >= 90:
                    st.success("✅ Excelente taxa de atividade!")
                elif activity_rate >= 70:
                    st.info("ℹ️ Boa taxa de atividade")
                else:
                    st.warning("⚠️ Taxa de atividade baixa")
            
            with col2:
                st.metric("🔐 Taxa de Adoção MFA", f"{mfa_rate:.1f}%")
                
                if mfa_rate >= 80:
                    st.success("✅ Excelente adoção de MFA!")
                elif mfa_rate >= 50:
                    st.info("ℹ️ Boa adoção de MFA")
                else:
                    st.warning("⚠️ Baixa adoção de MFA")
        
        # Ações rápidas
        st.markdown("---")
        st.write("#### ⚡ Ações Rápidas")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Atualizar Estatísticas", use_container_width=True):
                st.rerun()
        
        with col2:
            if st.button("👥 Ver Lista Completa", use_container_width=True):
                st.session_state.admin_current_page = "user_management"
                st.rerun()
        
        with col3:
            if st.button("➕ Criar Usuário", use_container_width=True):
                st.session_state['creating_user'] = True
                st.rerun()
            
    except Exception as e:
        st.error(f"❌ Erro ao carregar estatísticas: {e}")
        logger.error(f"User statistics error: {e}")

def render_admin_dashboard():
    """Dashboard administrativo principal"""
    st.subheader("📊 Dashboard do Sistema")
    
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Estatísticas básicas
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        user_count = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM files")
        file_stats = cursor.fetchone()
        file_count = file_stats[0] or 0
        total_bytes = file_stats[1] or 0
        total_gb = total_bytes / (1024**3) if total_bytes else 0
        
        cursor.execute("SELECT COUNT(*) FROM files WHERE DATE(uploaded_at) = CURRENT_DATE")
        files_today = cursor.fetchone()[0] or 0
        
        # Métricas principais
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("👥 Usuários", f"{user_count:,}")
        
        with col2:
            st.metric("📄 Arquivos", f"{file_count:,}")
        
        with col3:
            st.metric("💾 Armazenamento", f"{total_gb:.2f} GB")
        
        with col4:
            st.metric("📤 Hoje", f"{files_today:,}")
        
        st.markdown("---")
        
        # Link destacado para relatórios avançados
        st.info("💡 **Novo!** Acesse os **Relatórios Avançados** para análises detalhadas com gráficos interativos!")
        
        if st.button("🚀 Ir para Relatórios Avançados", type="primary", use_container_width=True):
            st.session_state.admin_current_page = "advanced_reports"
            st.rerun()
        
        st.markdown("---")
        
        # Ações rápidas
        st.subheader("⚡ Ações Rápidas")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("👥 Gerenciar Usuários", use_container_width=True):
                st.session_state.admin_current_page = "user_management"
                st.rerun()
        
        with col2:
            if st.button("📁 Ver Todos os Arquivos", use_container_width=True):
                st.session_state.admin_current_page = "files"
                st.rerun()
        
        with col3:
            if st.button("📊 Relatórios Detalhados", use_container_width=True):
                st.session_state.admin_current_page = "advanced_reports"
                st.rerun()
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        st.error(f"❌ Erro ao carregar dashboard: {e}")
        logger.error(f"Dashboard error: {e}")

def render_admin_users():
    """Lista detalhada de usuários"""
    st.subheader("👥 Administração de Usuários")
    
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Estatísticas de usuários
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        active_users = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE mfa_enabled = TRUE")
        mfa_users = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '30 days'")
        new_users = cursor.fetchone()[0] or 0
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Usuários Ativos", f"{active_users:,}")
        
        with col2:
            st.metric("Com MFA", f"{mfa_users:,}")
        
        with col3:
            st.metric("Novos (30d)", f"{new_users:,}")
        
        st.markdown("---")
        
        # Lista de usuários
        try:
            # Tentar tabela estendida primeiro
            cursor.execute("""
                SELECT username, full_name, email, role, status, created_at, last_login, mfa_enabled
                FROM users_extended
                WHERE is_active = TRUE
                ORDER BY created_at DESC 
                LIMIT 50
            """)
            users = cursor.fetchall()
            columns = ['username', 'full_name', 'email', 'role', 'status', 'created_at', 'last_login', 'mfa_enabled']
            
        except:
            # Fallback para tabela básica
            cursor.execute("""
                SELECT username, email, created_at, mfa_enabled
                FROM users
                WHERE is_active = TRUE
                ORDER BY created_at DESC 
                LIMIT 50
            """)
            users = cursor.fetchall()
            columns = ['username', 'email', 'created_at', 'mfa_enabled']
        
        if users:
            st.write(f"**📊 {len(users)} usuários (últimos 50)**")
            
            # Criar DataFrame para melhor visualização
            df = pd.DataFrame(users, columns=columns)
            
            # Formatação das colunas
            if 'created_at' in df.columns:
                df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%d/%m/%Y')
            
            if 'last_login' in df.columns:
                df['last_login'] = pd.to_datetime(df['last_login']).dt.strftime('%d/%m/%Y %H:%M')
            
            # Renomear colunas para português
            rename_map = {
                'username': 'Usuário',
                'full_name': 'Nome Completo',
                'email': 'Email',
                'role': 'Papel',
                'status': 'Status',
                'created_at': 'Criado em',
                'last_login': 'Último Login',
                'mfa_enabled': 'MFA'
            }
            
            df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})
            
            # Mostrar tabela
            st.dataframe(df, use_container_width=True)
            
        else:
            st.info("Nenhum usuário encontrado")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        st.error(f"Erro ao carregar usuários: {e}")
        logger.error(f"Users admin error: {e}")

def render_admin_files():
    """Lista detalhada de arquivos"""
    st.subheader("📁 Administração de Arquivos")
    
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Estatísticas de arquivos
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM files")
        file_stats = cursor.fetchone()
        total_files = file_stats[0] or 0
        total_bytes = file_stats[1] or 0
        total_gb = total_bytes / (1024**3) if total_bytes else 0
        
        cursor.execute("SELECT COUNT(*) FROM files WHERE DATE(uploaded_at) = CURRENT_DATE")
        files_today = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(DISTINCT uploaded_by) FROM files")
        unique_uploaders = cursor.fetchone()[0] or 0
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Arquivos", f"{total_files:,}")
        
        with col2:
            st.metric("Armazenamento", f"{total_gb:.2f} GB")
        
        with col3:
            st.metric("Hoje", f"{files_today:,}")
        
        with col4:
            st.metric("Usuários Ativos", f"{unique_uploaders:,}")
        
        st.markdown("---")
        
        # Lista básica de arquivos
        cursor.execute("""
            SELECT original_name, uploaded_by, file_size, uploaded_at, file_key
            FROM files
            ORDER BY uploaded_at DESC 
            LIMIT 50
        """)
        
        files = cursor.fetchall()
        
        if files:
            st.write(f"**📊 {len(files)} arquivos mais recentes**")
            
            for idx, (original_name, uploaded_by, file_size, uploaded_at, file_key) in enumerate(files):
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                    
                    with col1:
                        admin_badge = " 🛡️" if is_admin_user(uploaded_by) else ""
                        st.write(f"**📄 {original_name}**")
                        st.caption(f"👤 {uploaded_by}{admin_badge}")
                    
                    with col2:
                        size_mb = (file_size or 0) / (1024*1024)
                        if size_mb >= 1024:
                            size_display = f"{size_mb/1024:.2f} GB"
                        else:
                            size_display = f"{size_mb:.1f} MB"
                        st.write(f"📊 {size_display}")
                    
                    with col3:
                        if uploaded_at:
                            st.caption(f"📅 {uploaded_at.strftime('%d/%m/%Y')}")
                            st.caption(f"🕒 {uploaded_at.strftime('%H:%M')}")
                    
                    with col4:
                        if st.button("🗑️", key=f"admin_del_{idx}", help="Deletar arquivo"):
                            if delete_file_admin(file_key, original_name):
                                st.success(f"✅ {original_name} deletado!")
                                st.rerun()
                    
                    st.divider()
        
        else:
            st.info("Nenhum arquivo encontrado")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        st.error(f"Erro ao carregar arquivos: {e}")
        logger.error(f"Files admin error: {e}")

def delete_file_admin(file_key: str, filename: str) -> bool:
    """Deleta arquivo como admin"""
    try:
        from s3_manager import S3Manager
        from database import DatabaseManager
        from config import Config
        
        # Deletar do S3
        s3_manager = S3Manager(
            Config.AWS_ACCESS_KEY_ID,
            Config.AWS_SECRET_ACCESS_KEY,
            Config.AWS_REGION,
            Config.S3_BUCKET
        )
        
        s3_deleted = s3_manager.delete_file(file_key)
        
        # Deletar do banco
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM files WHERE file_key = %s", (file_key,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        # Log de sucesso
        logger.info(f"Admin deleted file: {filename} ({file_key})")
            
        return True
        
    except Exception as e:
        logger.error(f"Admin file deletion error: {e}")
        st.error(f"Erro ao deletar: {e}")
        return False

def render_reports_section(username: str, user_manager=None):
    """Seção de relatórios básicos"""
    st.subheader("📈 Relatórios Básicos do Sistema")
    
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Período de análise
        period_days = st.selectbox(
            "Período de análise:",
            [7, 15, 30, 60, 90],
            index=2,
            format_func=lambda x: f"Últimos {x} dias"
        )
        
        st.markdown("---")
        
        # Relatório de atividade
        st.write("### 📊 Atividade Recente")
        
        # Uploads por dia
        cursor.execute(f"""
            SELECT DATE(uploaded_at) as dia, COUNT(*) as uploads,
                   COALESCE(SUM(file_size), 0) as bytes_total
            FROM files 
            WHERE uploaded_at >= NOW() - INTERVAL '{period_days or 30} days'
            GROUP BY DATE(uploaded_at)
            ORDER BY dia DESC
        """)
        
        daily_activity = cursor.fetchall()
        
        if daily_activity:
            st.write("**📤 Atividade dos últimos dias:**")
            for day, uploads, bytes_total in daily_activity:
                gb_total = bytes_total / (1024**3) if bytes_total else 0
                st.write(f"• **{day.strftime('%d/%m/%Y')}**: {uploads} uploads ({gb_total:.2f} GB)")
        
        st.markdown("---")
        
        # Top usuários
        st.write("### 🏆 Top Usuários por Uploads")
        
        cursor.execute(f"""
            SELECT uploaded_by, COUNT(*) as total_uploads,
                   COALESCE(SUM(file_size), 0) as total_bytes
            FROM files 
            WHERE uploaded_at >= NOW() - INTERVAL '{period_days} days'
            GROUP BY uploaded_by
            ORDER BY COUNT(*) DESC
            LIMIT 10
        """)
        
        top_users = cursor.fetchall()
        
        if top_users:
            for user, uploads, bytes_total in top_users:
                gb_total = bytes_total / (1024**3) if bytes_total else 0
                admin_badge = " 🛡️" if is_admin_user(user) else ""
                st.write(f"• **{user}{admin_badge}**: {uploads} arquivos ({gb_total:.2f} GB)")
        
        cursor.close()
        conn.close()
        
        # Link para relatórios avançados
        st.markdown("---")
        st.info("💡 **Quer mais detalhes?** Acesse os **Relatórios Avançados** para gráficos interativos!")
        
        if st.button("🚀 Ir para Relatórios Avançados", type="primary"):
            st.session_state.admin_current_page = "advanced_reports"
            st.rerun()
        
    except Exception as e:
        st.error(f"Erro nos relatórios básicos: {e}")
        logger.error(f"Basic reports error: {e}")

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
        st.info("Execute o comando abaixo para instalar as dependências:")
        
        st.code("pip install plotly>=5.15.0 pandas>=1.5.0 numpy>=1.24.0 matplotlib>=3.6.0 seaborn>=0.12.0")
        
        # Verificar quais dependências estão faltando
        missing_deps = []
        
        try:
            import plotly
        except ImportError:
            missing_deps.append("plotly")
        
        try:
            import pandas
        except ImportError:
            missing_deps.append("pandas")
        
        try:
            import numpy
        except ImportError:
            missing_deps.append("numpy")
        
        if missing_deps:
            st.warning(f"Dependências faltando: {', '.join(missing_deps)}")
        
        # Fallback para relatórios básicos
        st.markdown("---")
        st.warning("📊 Usando relatórios básicos como alternativa")
        render_reports_section(username, user_manager)
        
    except Exception as e:
        logger.error(f"Advanced reports error: {e}")
        st.error(f"❌ Erro nos relatórios avançados: {e}")
        
        # Informações de debug simplificadas
        with st.expander("🔍 Informações de Debug"):
            st.write("**Erro:**", str(e))
            st.write("**Usuário:**", username)
            st.write("**Timestamp:**", datetime.now().isoformat())
        
        # Tentar relatórios básicos como fallback
        st.markdown("---")
        st.warning("📊 Tentando carregar relatórios básicos...")
        try:
            render_reports_section(username, user_manager)
        except Exception as fallback_error:
            st.error(f"❌ Erro também nos relatórios básicos: {fallback_error}")

def render_system_logs_section():
    """Seção para visualização de logs do sistema"""
    st.subheader("📋 Logs do Sistema")
    
    try:
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Verificar se tabela de logs existe
        try:
            cursor.execute("""
                SELECT admin_username, action, target_username, timestamp, 
                       ip_address, details, success
                FROM admin_logs
                ORDER BY timestamp DESC
                LIMIT 100
            """)
            
            logs = cursor.fetchall()
            
            if logs:
                st.write("### 📋 Logs Administrativos (últimos 100)")
                
                # Lista de logs
                for log in logs[:20]:  # Mostrar apenas 20 para performance
                    admin_username, action, target_username, timestamp, ip_address, details, success = log
                    
                    with st.container():
                        col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
                        
                        with col1:
                            status_icon = "✅" if success else "❌"
                            st.write(f"{status_icon} **{action}**")
                            st.caption(f"👤 Admin: {admin_username}")
                        
                        with col2:
                            if target_username:
                                st.write(f"🎯 Alvo: {target_username}")
                            st.caption(f"🌐 IP: {ip_address or 'N/A'}")
                        
                        with col3:
                            st.caption(f"📅 {timestamp.strftime('%d/%m/%Y')}")
                            st.caption(f"🕒 {timestamp.strftime('%H:%M:%S')}")
                        
                        with col4:
                            if details:
                                if st.button("📋", key=f"details_{timestamp}", help="Ver detalhes"):
                                    st.info(f"Detalhes: {details}")
                        
                        st.divider()
            
            else:
                st.info("📋 Nenhum log administrativo encontrado")
        
        except Exception as e:
            st.info("⚠️ Tabela de logs não disponível")
            st.write("Para habilitar logs administrativos, certifique-se de que o sistema de gerenciamento de usuários esteja ativo.")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        st.error(f"❌ Erro ao carregar logs: {e}")
        logger.error(f"System logs error: {e}")

# Funções auxiliares
def _basic_admin_check(username: str) -> bool:
    """Verificação básica de admin (fallback)"""
    return 'admin' in username.lower()

def _generate_temp_password(length: int = 12) -> str:
    """Gera senha temporária segura"""
    characters = string.ascii_letters + string.digits + "!@#$%&*"
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    # Garantir que tem pelo menos 1 maiúscula, 1 minúscula, 1 número e 1 símbolo
    while not (any(c.islower() for c in password) and 
               any(c.isupper() for c in password) and 
               any(c.isdigit() for c in password) and 
               any(c in "!@#$%&*" for c in password)):
        password = ''.join(secrets.choice(characters) for _ in range(length))
    
    return password

def _reset_user_password_simple(admin_username: str, target_username: str, new_password: str, user_manager) -> tuple[bool, str]:
    """Reset de senha simplificado"""
    try:
        # Hash da nova senha
        password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        # Atualizar usando o user_manager ou diretamente no banco
        from database import DatabaseManager
        from config import Config
        
        db_manager = DatabaseManager(Config.DATABASE_URL)
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Tentar atualizar na tabela estendida
        try:
            cursor.execute("""
                UPDATE users_extended 
                SET password_hash = %s, must_change_password = TRUE, updated_at = %s
                WHERE username = %s
            """, (password_hash, datetime.now(), target_username))
            
            if cursor.rowcount == 0:
                # Fallback para tabela básica
                cursor.execute("""
                    UPDATE users 
                    SET password_hash = %s
                    WHERE username = %s
                """, (password_hash, target_username))
        
        except:
            # Fallback para tabela básica
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s
                WHERE username = %s
            """, (password_hash, target_username))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return True, f"Senha resetada para {target_username}"
        
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return False, f"Erro ao resetar senha: {str(e)}"

# Função para verificação de admin (mantida para compatibilidade)
def is_admin_user(username: str) -> bool:
    """Verificação de admin - MAIS ROBUSTA E CONFIÁVEL"""
    return check_admin_permissions_comprehensive(username)

# Log de inicialização
logger.info("✅ Complete admin pages system with HARD DELETE functionality loaded successfully")
