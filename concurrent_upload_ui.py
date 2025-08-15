"""
Interface de Upload Simultâneo - VERSÃO COM SINTAXE CORRIGIDA
Arquivo: concurrent_upload_ui.py
Gerencia interface para múltiplos uploads simultâneos com correção de metadados
"""
import streamlit as st
import time
from datetime import datetime
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class ConcurrentUploadUI:
    """Interface para gerenciar uploads simultâneos - VERSÃO CORRIGIDA"""
    
    def __init__(self, s3_concurrent_manager, db_manager):
        self.s3_manager = s3_concurrent_manager
        self.db_manager = db_manager
        
        # CORREÇÃO: Verificar se concurrent_manager existe antes de usar
        if hasattr(s3_concurrent_manager, 'concurrent_manager'):
            self.concurrent_manager = s3_concurrent_manager.concurrent_manager
        else:
            self.concurrent_manager = None
            logger.warning("Concurrent manager not available - using basic upload")
    
    def render_upload_section(self, username: str):
        """Renderiza seção principal de upload"""
        
        # CORREÇÃO: Verificar se concurrent manager está disponível
        if not self.concurrent_manager:
            st.warning("⚠️ Sistema de uploads simultâneos indisponível")
            st.info("Usando sistema básico de upload...")
            self._render_basic_upload_fallback(username)
            return
        
        st.header("📤 Espaço Para Upload de Arquivos")
        
        # Status geral do sistema
        self._render_system_status()
        
        # Área de upload múltiplo
        self._render_multi_upload_area(username)
        
        # Monitor de uploads ativos
        self._render_active_uploads_monitor()
        
        # Histórico e estatísticas
        self._render_upload_history()
        
        # Seção de sincronização de metadados
        self._render_metadata_sync_section(username)
    
    def _render_system_status(self):
        """Renderiza status geral do sistema"""
        try:
            stats = self.concurrent_manager.get_system_statistics()
            
            st.subheader("📊 Status do Sistema")
            
            # Métricas principais
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.metric(
                    "Uploads Ativos", 
                    stats.get('active_uploads', 0),
                    f"Máx: {stats.get('max_concurrent', 10)}"
                )
            
            with col2:
                st.metric(
                    "Enviando Agora", 
                    stats.get('uploading_now', 0),
                    f"de {stats.get('max_concurrent', 10)}"
                )
            
            with col3:
                st.metric(
                    "Na Fila", 
                    stats.get('queued_uploads', 0)
                )
            
            with col4:
                st.metric(
                    "Concluídos", 
                    stats.get('completed_uploads', 0)
                )
            
            with col5:
                failed_count = stats.get('failed_uploads', 0)
                if failed_count > 0:
                    st.metric(
                        "Falharam", 
                        failed_count,
                        delta=f"-{failed_count}"
                    )
                else:
                    st.metric("Falharam", 0)
            
            # Barra de utilização
            max_concurrent = stats.get('max_concurrent', 1)
            uploading_now = stats.get('uploading_now', 0)
            
            if max_concurrent > 0:
                utilization = (uploading_now / max_concurrent) * 100
                st.progress(utilization / 100)
                st.caption(f"Utilização: {utilization:.1f}% ({uploading_now}/{max_concurrent} slots)")
            
        except Exception as e:
            st.error(f"Erro ao carregar status do sistema: {e}")
            logger.error(f"System status error: {e}")
    
    def _render_multi_upload_area(self, username: str):
        """Renderiza área de upload múltiplo"""
        st.subheader("📁 Selecionar Arquivos")
        
        # Upload múltiplo
        uploaded_files = st.file_uploader(
            "Escolha um ou mais arquivos:",
            accept_multiple_files=True,
            type=None,
            help="Selecione múltiplos arquivos para upload simultâneo"
        )
        
        if uploaded_files:
            self._render_file_selection_area(uploaded_files, username)
    
    def _render_file_selection_area(self, uploaded_files: List, username: str):
        """Renderiza área de seleção e configuração de arquivos"""
        st.write(f"### 📄 {len(uploaded_files)} Arquivo(s) Selecionado(s)")
        
        # Validações gerais
        max_file_size = 2 * 1024 * 1024 * 1024  # 2GB
        oversized_files = [f for f in uploaded_files if f.size > max_file_size]
        
        if oversized_files:
            st.error(f"❌ {len(oversized_files)} arquivo(s) muito grande(s) (máximo 2GB)")
            return
        
        # Lista de arquivos com configurações
        files_config = []
        
        for i, file in enumerate(uploaded_files):
            with st.container():
                col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                
                with col1:
                    st.write(f"**{file.name}**")
                    size_mb = file.size / (1024 * 1024)
                    if size_mb >= 1024:
                        size_display = f"{size_mb/1024:.2f} GB"
                    else:
                        size_display = f"{size_mb:.1f} MB"
                    
                    st.caption(f"📊 {size_display} • {file.type or 'Tipo desconhecido'}")
                
                with col2:
                    # Prioridade
                    priority = st.selectbox(
                        "Prioridade",
                        [1, 2, 3],
                        format_func=lambda x: {1: "🔴 Alta", 2: "🟡 Normal", 3: "🟢 Baixa"}[x],
                        index=1,  # Normal por padrão
                        key=f"priority_{i}"
                    )
                
                with col3:
                    # Nome único será gerado automaticamente
                    try:
                        unique_name, _ = self.concurrent_manager.generate_unique_filename(file.name, username)
                        if unique_name != file.name:
                            st.caption(f"📝 Será salvo como:")
                            st.caption(f"**{unique_name}**")
                        else:
                            st.caption("✅ Nome original")
                    except Exception as e:
                        logger.error(f"Error generating unique name: {e}")
                        unique_name = file.name
                        st.caption("✅ Nome original")
                
                with col4:
                    # Incluir no upload
                    include = st.checkbox(
                        "Incluir",
                        value=True,
                        key=f"include_{i}"
                    )
                
                if include:
                    files_config.append({
                        'file': file,
                        'priority': priority,
                        'unique_name': unique_name
                    })
                
                st.divider()
        
        # Resumo e botão de upload
        if files_config:
            selected_count = len(files_config)
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**📋 Resumo: {selected_count} arquivo(s) selecionado(s)**")
            
            with col2:
                # Botão de upload
                if st.button("🚀 Iniciar Uploads", type="primary", use_container_width=True):
                    self._start_batch_upload(files_config, username)
    
    def _start_batch_upload(self, files_config: List[Dict], username: str):
        """Inicia batch de uploads"""
        try:
            upload_ids = []
            
            for config in files_config:
                file_obj = config['file']
                priority = config['priority']
                
                # Iniciar upload
                upload_id = self.s3_manager.upload_file_concurrent(
                    file_obj=file_obj,
                    file_name=file_obj.name,
                    username=username,
                    priority=priority
                )
                
                upload_ids.append(upload_id)
                logger.info(f"Started upload: {upload_id} for {file_obj.name}")
            
            # Feedback de sucesso
            st.success(f"✅ {len(upload_ids)} upload(s) iniciado(s)!")
            st.info("👁️ Acompanhe o progresso na seção de monitoramento abaixo")
            
            # Rerun para atualizar interface
            time.sleep(1)
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Erro ao iniciar uploads: {str(e)}")
            logger.error(f"Batch upload error: {e}")
    
    def _render_active_uploads_monitor(self):
        """Renderiza monitor de uploads ativos"""
        try:
            active_uploads = self.concurrent_manager.get_all_active_uploads()
            
            if not active_uploads:
                st.info("💤 Nenhum upload ativo no momento")
                return
            
            st.subheader(f"🔄 Uploads Ativos ({len(active_uploads)})")
            
            # Container para atualizações em tempo real
            monitor_container = st.container()
            
            with monitor_container:
                for session in active_uploads:
                    self._render_upload_progress_card(session)
            
            # Auto-refresh
            if active_uploads:
                time.sleep(2)
                st.rerun()
                
        except Exception as e:
            st.error(f"Erro ao carregar uploads ativos: {e}")
            logger.error(f"Active uploads monitor error: {e}")
    
    def _render_upload_progress_card(self, session):
        """Renderiza card de progresso individual"""
        try:
            with st.container():
                # Header do card
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    # Status icon baseado no status
                    status_icons = {
                        'initializing': '🔄',
                        'queued': '⏳',
                        'uploading': '📤',
                        'completed': '✅',
                        'failed': '❌',
                        'cancelled': '🚫'
                    }
                    
                    icon = status_icons.get(session.status, '❓')
                    st.write(f"{icon} **{session.file_name}**")
                
                with col2:
                    # Prioridade
                    priority_display = {1: "🔴 Alta", 2: "🟡 Normal", 3: "🟢 Baixa"}
                    st.caption(f"Prioridade: {priority_display.get(session.priority, 'N/A')}")
                
                with col3:
                    # Ações
                    if session.status in ['uploading', 'queued']:
                        if st.button("❌ Cancelar", key=f"cancel_{session.id}", use_container_width=True):
                            if self.concurrent_manager.cancel_upload(session.id):
                                st.success("Upload cancelado!")
                                st.rerun()
                
                # Progresso detalhado
                if session.status == 'uploading':
                    # Barra de progresso
                    progress = getattr(session, 'progress_percentage', 0) / 100
                    st.progress(progress)
                    
                    # Métricas básicas
                    st.caption(f"Progresso: {getattr(session, 'progress_percentage', 0):.1f}%")
                    st.caption(f"Velocidade: {getattr(session, 'speed_mbps', 0):.1f} MB/s")
                
                st.markdown("---")
                
        except Exception as e:
            st.error(f"Erro ao renderizar progresso: {e}")
            logger.error(f"Progress card error: {e}")
    
    def _render_upload_history(self):
        """Renderiza histórico de uploads"""
        try:
            st.subheader("📚 Histórico de Uploads")
            
            # Tabs para diferentes categorias
            tab1, tab2 = st.tabs(["✅ Concluídos", "❌ Falharam"])
            
            with tab1:
                self._render_completed_uploads()
            
            with tab2:
                self._render_failed_uploads()
                
        except Exception as e:
            st.error(f"Erro ao carregar histórico: {e}")
            logger.error(f"Upload history error: {e}")
    
    def _render_completed_uploads(self):
        """Renderiza uploads concluídos"""
        try:
            completed = list(self.concurrent_manager.completed_uploads.values())
            
            if not completed:
                st.info("📂 Nenhum upload concluído nesta sessão")
                return
            
            # Ordenar por mais recente
            completed.sort(key=lambda x: x.start_time, reverse=True)
            
            st.write(f"**{len(completed)} upload(s) concluído(s)**")
            
            for session in completed[:10]:  # Mostrar últimos 10
                with st.expander(f"✅ {session.file_name}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Arquivo:** {getattr(session, 'original_file_name', session.file_name)}")
                        st.write(f"**Tamanho:** {self._format_bytes(session.file_size)}")
                        
                        # Botão para salvar metadados
                        if not getattr(session, 'metadata_saved', False):
                            if st.button(f"💾 Concluir Upload", key=f"save_meta_{session.id}"):
                                if self._save_file_metadata(session):
                                    session.metadata_saved = True
                                    st.success("✅ Arquivos salvos!")
                                    st.rerun()
                                else:
                                    st.error("❌ Erro ao salvar metadados")
                        else:
                            st.success("✅ Metadados já salvos no banco")
                    
                    with col2:
                        # Calcular estatísticas
                        if hasattr(session, 'start_time'):
                            end_time = getattr(session, 'end_time', time.time())
                            total_time = end_time - session.start_time
                            speed = (session.file_size / (1024 * 1024)) / total_time if total_time > 0 else 0
                            
                            st.write(f"**Velocidade:** {speed:.1f} MB/s")
                            st.write(f"**Tempo:** {self._format_time(total_time)}")
                            
        except Exception as e:
            st.error(f"Erro ao carregar uploads concluídos: {e}")
            logger.error(f"Completed uploads error: {e}")
    
    def _render_failed_uploads(self):
        """Renderiza uploads falhados"""
        try:
            failed = list(self.concurrent_manager.failed_uploads.values())
            
            if not failed:
                st.success("🎉 Nenhum upload falhado!")
                return
            
            st.write(f"**{len(failed)} upload(s) falharam**")
            
            for session in failed:
                with st.expander(f"❌ {session.file_name}", expanded=False):
                    error_msg = getattr(session, 'error_message', 'Erro desconhecido')
                    st.error(f"**Erro:** {error_msg}")
                    st.write(f"**Arquivo:** {getattr(session, 'original_file_name', session.file_name)}")
                    
        except Exception as e:
            st.error(f"Erro ao carregar uploads falhados: {e}")
            logger.error(f"Failed uploads error: {e}")
    
    def _render_metadata_sync_section(self, username: str):
        """Seção para sincronização de metadados"""
        try:
            st.subheader("🔄 Sincronização de Metadados")
            
            with st.expander("💾 Garantir que arquivos apareçam em 'Meus Arquivos'", expanded=False):
                st.write("""
                **Por que usar esta seção?**
                - Às vezes os uploads simultâneos completam mas os metadados não são salvos no banco
                - Isso faz com que os arquivos existam no S3 mas não apareçam em "Meus Arquivos"
                - Use as ferramentas abaixo para sincronizar
                """)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("🔄 Sincronizar Uploads Concluídos", use_container_width=True):
                        self._sync_completed_uploads()
                
                with col2:
                    if st.button("🔍 Buscar Arquivos Órfãos no S3", use_container_width=True):
                        self._find_orphaned_files(username)
                        
        except Exception as e:
            st.error(f"Erro na seção de metadados: {e}")
            logger.error(f"Metadata sync error: {e}")
    
    def _sync_completed_uploads(self):
        """Sincroniza uploads concluídos que não salvaram metadados"""
        try:
            completed = list(self.concurrent_manager.completed_uploads.values())
            
            if not completed:
                st.info("📂 Nenhum upload concluído para sincronizar")
                return
            
            synced_count = 0
            
            for session in completed:
                if not getattr(session, 'metadata_saved', False):
                    try:
                        if self._save_file_metadata(session):
                            session.metadata_saved = True
                            synced_count += 1
                            st.write(f"✅ Sincronizado: {getattr(session, 'original_file_name', session.file_name)}")
                    except Exception as e:
                        st.write(f"❌ Erro em {getattr(session, 'original_file_name', session.file_name)}: {str(e)}")
            
            if synced_count > 0:
                st.success(f"🎉 {synced_count} arquivo(s) sincronizado(s)!")
            else:
                st.info("ℹ️ Todos os uploads já estão sincronizados")
                    
        except Exception as e:
            st.error(f"Erro na sincronização: {e}")
            logger.error(f"Sync completed uploads error: {e}")
    
    def _find_orphaned_files(self, username: str):
        """Busca arquivos órfãos no S3 que não estão no banco"""
        try:
            import boto3
            
            # Usar as credenciais do S3Manager
            s3_client = self.s3_manager.s3_manager.s3_client
            bucket = self.s3_manager.s3_manager.bucket
            
            # Listar arquivos do usuário no S3
            prefix = f"{username}/"
            
            with st.spinner("🔍 Buscando arquivos órfãos..."):
                response = s3_client.list_objects_v2(
                    Bucket=bucket,
                    Prefix=prefix
                )
                
                if 'Contents' not in response:
                    st.info("📂 Nenhum arquivo encontrado no S3")
                    return
                
                s3_files = response['Contents']
                
                # Verificar quais não estão no banco
                conn = self.db_manager.get_connection()
                cursor = conn.cursor()
                
                orphaned_files = []
                
                for s3_file in s3_files:
                    file_key = s3_file['Key']
                    
                    cursor.execute("SELECT COUNT(*) FROM files WHERE file_key = %s", (file_key,))
                    exists = cursor.fetchone()[0] > 0
                    
                    if not exists:
                        orphaned_files.append({
                            'file_key': file_key,
                            'size': s3_file['Size'],
                            'last_modified': s3_file['LastModified']
                        })
                
                cursor.close()
                conn.close()
                
                if orphaned_files:
                    st.warning(f"⚠️ Encontrados {len(orphaned_files)} arquivo(s) órfão(s):")
                    
                    for file_info in orphaned_files:
                        file_key = file_info['file_key']
                        original_name = file_key.split('/')[-1]
                        
                        # Remover timestamp se presente
                        if '_' in original_name:
                            parts = original_name.split('_', 1)
                            if len(parts) > 1:
                                original_name = parts[1]
                        
                        col1, col2 = st.columns([3, 1])
                        
                        with col1:
                            st.write(f"📄 **{original_name}**")
                            st.caption(f"S3: {file_key}")
                            st.caption(f"Tamanho: {self._format_bytes(file_info['size'])}")
                        
                        with col2:
                            if st.button(f"💾 Adicionar", key=f"add_{file_key}", use_container_width=True):
                                try:
                                    # Detectar MIME type
                                    import mimetypes
                                    mime_type, _ = mimetypes.guess_type(original_name)
                                    if not mime_type:
                                        mime_type = "application/octet-stream"
                                    
                                    # Salvar no banco
                                    self.db_manager.save_file_metadata(
                                        file_key=file_key,
                                        original_name=original_name,
                                        file_size=file_info['size'],
                                        username=username,
                                        mime_type=mime_type
                                    )
                                    
                                    st.success(f"✅ {original_name} adicionado!")
                                    st.rerun()
                                    
                                except Exception as e:
                                    st.error(f"❌ Erro: {str(e)}")
                        
                        st.divider()
                else:
                    st.success("✅ Todos os arquivos estão sincronizados!")
                    
        except Exception as e:
            st.error(f"❌ Erro ao buscar arquivos órfãos: {str(e)}")
            logger.error(f"Orphaned files search error: {e}")
    
    def _save_file_metadata(self, session):
        """Salva metadados do arquivo no banco"""
        try:
            # Verificar se session tem todos os dados necessários
            if not hasattr(session, 'file_key') or not session.file_key:
                logger.error(f"Session {session.id} missing file_key")
                return False
                
            original_file_name = getattr(session, 'original_file_name', session.file_name)
            if not original_file_name:
                logger.error(f"Session {session.id} missing original_file_name")
                return False
                
            if not hasattr(session, 'file_size') or not session.file_size:
                logger.error(f"Session {session.id} missing file_size")
                return False
                
            if not hasattr(session, 'username') or not session.username:
                logger.error(f"Session {session.id} missing username")
                return False

            # Salvar no banco
            self.db_manager.save_file_metadata(
                file_key=session.file_key,
                original_name=original_file_name,
                file_size=session.file_size,
                username=session.username,
                mime_type=getattr(session, 'file_type', None) or "application/octet-stream"
            )
            
            logger.info(f"✅ Metadata saved successfully for: {session.file_key}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saving metadata for session {session.id}: {e}")
            return False
    
    def _render_basic_upload_fallback(self, username: str):
        """Fallback para upload básico"""
        st.header("📤 Upload de Arquivo")
        
        uploaded_file = st.file_uploader("Escolha um arquivo:", type=None)
        
        if uploaded_file is not None:
            if st.button("🚀 Fazer Upload", type="primary"):
                try:
                    # Gerar nome único simples
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    file_key = f"{username}/{timestamp}_{uploaded_file.name}"
                    
                    with st.spinner("Fazendo upload..."):
                        # Upload
                        if self.s3_manager.upload_file(uploaded_file, file_key):
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
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Formata bytes para leitura humana"""
        if bytes_value < 1024:
            return f"{bytes_value} B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value / 1024:.1f} KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"
    
    def _format_time(self, seconds: float) -> str:
        """Formata tempo para leitura humana"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours:.0f}h {minutes:.0f}m"


# Função principal para integração - VERSÃO CORRIGIDA
def render_concurrent_upload_section(s3_manager, db_manager, username: str):
    """Renderiza seção completa de upload simultâneo - VERSÃO CORRIGIDA"""
    try:
        # CORREÇÃO: Importação condicional e tratamento de erro
        try:
            from enhanced_upload_monitor import get_s3_concurrent_manager
            
            # Obter manager de uploads simultâneos
            s3_concurrent_manager = get_s3_concurrent_manager(s3_manager)
            
            # Criar e renderizar UI
            upload_ui = ConcurrentUploadUI(s3_concurrent_manager, db_manager)
            upload_ui.render_upload_section(username)
            
        except ImportError as import_error:
            logger.warning(f"Enhanced upload monitor not available: {import_error}")
            # Fallback para upload básico
            st.warning("⚠️ Sistema de upload simultâneo não disponível")
            st.info("Usando sistema básico de upload...")
            _render_basic_upload_fallback(s3_manager, db_manager, username)
            
        except Exception as enhanced_error:
            logger.error(f"Enhanced upload system error: {enhanced_error}")
            # Fallback para upload básico em caso de qualquer erro
            st.warning("⚠️ Erro no sistema de upload avançado")
            st.info("Usando sistema básico de upload como fallback...")
            _render_basic_upload_fallback(s3_manager, db_manager, username)
        
    except Exception as e:
        logger.error(f"Critical error in concurrent upload section: {e}")
        st.error(f"❌ Erro crítico no sistema de upload: {str(e)}")
        
        # Último fallback - upload básico mínimo
        st.info("Tentando sistema básico de emergência...")
        _render_emergency_upload_fallback(s3_manager, db_manager, username)


def _render_basic_upload_fallback(s3_manager, db_manager, username: str):
    """Fallback para upload básico"""
    st.header("📤 Upload de Arquivo")
    
    uploaded_file = st.file_uploader("Escolha um arquivo:", type=None)
    
    if uploaded_file is not None:
        # Mostrar informações do arquivo
        st.write(f"**Nome:** {uploaded_file.name}")
        st.write(f"**Tamanho:** {uploaded_file.size:,} bytes")
        st.write(f"**Tipo:** {uploaded_file.type or 'Desconhecido'}")
        
        if st.button("🚀 Fazer Upload", type="primary"):
            try:
                # Gerar nome único simples
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                file_key = f"{username}/{timestamp}_{uploaded_file.name}"
                
                with st.spinner("Fazendo upload..."):
                    # Upload
                    if s3_manager.upload_file(uploaded_file, file_key):
                        # Salvar metadados
                        db_manager.save_file_metadata(
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
                logger.error(f"Basic upload error: {e}")


def _render_emergency_upload_fallback(s3_manager, db_manager, username: str):
    """Fallback de emergência - ultra básico"""
    try:
        st.header("📤 Upload de Emergência")
        st.warning("Sistema básico de emergência ativo")
        
        uploaded_file = st.file_uploader("Arquivo:", type=None, key="emergency_upload")
        
        if uploaded_file is not None:
            if st.button("Upload", type="primary", key="emergency_button"):
                try:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    file_key = f"{username}/{timestamp}_{uploaded_file.name}"
                    
                    if s3_manager.upload_file(uploaded_file, file_key):
                        st.success("✅ Upload realizado")
                    else:
                        st.error("❌ Erro no upload")
                        
                except Exception as e:
                    st.error(f"Erro: {str(e)}")
                    
    except Exception as e:
        st.error(f"Erro crítico: {str(e)}")
        logger.error(f"Emergency upload error: {e}")


# Log de inicialização
logger.info("✅ Concurrent upload UI loaded successfully with error handling")
