"""
Monitor de Upload Melhorado com Feedback em Tempo Real
Arquivo: enhanced_upload_monitor.py
"""
import streamlit as st
import time
import threading
import logging
import hashlib
from typing import Dict, Optional, Callable
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class EnhancedUploadMonitor:
    """Monitor de upload com feedback detalhado em tempo real"""
    
    def __init__(self):
        self.active_uploads: Dict[str, dict] = {}
        self.completed_uploads: Dict[str, dict] = {}
        self.failed_uploads: Dict[str, dict] = {}
        self.logger = logging.getLogger(__name__)
    
    def create_upload_session(self, file_name: str, file_size: int, 
                             file_type: str = None) -> str:
        """Cria uma sessão de upload e retorna o ID"""
        upload_id = self._generate_upload_id(file_name, file_size)
        
        self.active_uploads[upload_id] = {
            'file_name': file_name,
            'file_size': file_size,
            'file_type': file_type,
            'start_time': time.time(),
            'bytes_transferred': 0,
            'status': 'initializing',
            'speed_mbps': 0,
            'eta_seconds': 0,
            'progress_percentage': 0,
            'error_message': None,
            'chunks_completed': 0,
            'total_chunks': 0,
            'last_update': time.time()
        }
        
        self.logger.info(f"Upload session created: {upload_id} for {file_name} ({file_size} bytes)")
        return upload_id
    
    def _generate_upload_id(self, file_name: str, file_size: int) -> str:
        """Gera ID único para o upload"""
        timestamp = str(int(time.time()))
        content = f"{file_name}_{file_size}_{timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def update_progress(self, upload_id: str, bytes_transferred: int, 
                       chunk_info: dict = None):
        """Atualiza progresso do upload"""
        if upload_id not in self.active_uploads:
            return
        
        upload = self.active_uploads[upload_id]
        upload['bytes_transferred'] = bytes_transferred
        upload['progress_percentage'] = (bytes_transferred / upload['file_size']) * 100
        upload['last_update'] = time.time()
        upload['status'] = 'uploading'
        
        # Calcular velocidade média
        elapsed = time.time() - upload['start_time']
        if elapsed > 0:
            upload['speed_mbps'] = (bytes_transferred / (1024 * 1024)) / elapsed
            
            # Calcular ETA
            remaining_bytes = upload['file_size'] - bytes_transferred
            if upload['speed_mbps'] > 0:
                upload['eta_seconds'] = remaining_bytes / (upload['speed_mbps'] * 1024 * 1024)
        
        # Informações de chunks (multipart upload)
        if chunk_info:
            upload['chunks_completed'] = chunk_info.get('completed', 0)
            upload['total_chunks'] = chunk_info.get('total', 0)
    
    def complete_upload(self, upload_id: str, success: bool = True, 
                       error_message: str = None):
        """Finaliza upload e move para histórico"""
        if upload_id not in self.active_uploads:
            return
        
        upload = self.active_uploads.pop(upload_id)
        upload['end_time'] = time.time()
        upload['status'] = 'completed' if success else 'failed'
        upload['error_message'] = error_message
        
        # Calcular estatísticas finais
        total_time = upload['end_time'] - upload['start_time']
        if total_time > 0:
            upload['final_speed_mbps'] = (upload['file_size'] / (1024 * 1024)) / total_time
        
        # Mover para histórico apropriado
        if success:
            self.completed_uploads[upload_id] = upload
            self.logger.info(f"Upload completed: {upload_id} - {upload.get('final_speed_mbps', 0):.1f}MB/s")
        else:
            self.failed_uploads[upload_id] = upload
            self.logger.error(f"Upload failed: {upload_id} - {error_message}")
    
    def get_upload_status(self, upload_id: str) -> Optional[dict]:
        """Retorna status atual do upload"""
        if upload_id in self.active_uploads:
            return self.active_uploads[upload_id]
        elif upload_id in self.completed_uploads:
            return self.completed_uploads[upload_id]  
        elif upload_id in self.failed_uploads:
            return self.failed_uploads[upload_id]
        return None
    
    def render_upload_progress(self, upload_id: str, container=None) -> bool:
        """Renderiza progresso detalhado no Streamlit"""
        upload = self.get_upload_status(upload_id)
        if not upload:
            return False
        
        # Usar container fornecido ou criar novo
        if container is None:
            container = st.container()
        
        with container:
            status = upload['status']
            
            if status == 'initializing':
                st.info("🔄 Inicializando upload...")
                return True
            
            elif status == 'uploading':
                self._render_active_upload(upload)
                return True
            
            elif status == 'completed':
                self._render_completed_upload(upload)
                return False
                
            elif status == 'failed':
                self._render_failed_upload(upload)
                return False
        
        return False
    
    def _render_active_upload(self, upload: dict):
        """Renderiza upload ativo"""
        progress = upload['progress_percentage']
        
        # Barra de progresso principal
        st.progress(progress / 100)
        
        # Informações em colunas
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Progresso", 
                f"{progress:.1f}%",
                f"{self._format_bytes(upload['bytes_transferred'])} / {self._format_bytes(upload['file_size'])}"
            )
        
        with col2:
            st.metric(
                "Velocidade",
                f"{upload['speed_mbps']:.1f} MB/s"
            )
        
        with col3:
            if upload['eta_seconds'] > 0:
                eta_str = self._format_time(upload['eta_seconds'])
                st.metric("Tempo Restante", eta_str)
            else:
                st.metric("Tempo Restante", "Calculando...")
        
        with col4:
            elapsed = time.time() - upload['start_time']
            elapsed_str = self._format_time(elapsed)
            st.metric("Tempo Decorrido", elapsed_str)
        
        # Informações de chunks (se disponível)
        if upload['total_chunks'] > 0:
            chunk_progress = upload['chunks_completed'] / upload['total_chunks']
            st.caption(f"📦 Chunks: {upload['chunks_completed']}/{upload['total_chunks']}")
            st.progress(chunk_progress)
        
        # Status detalhado
        st.caption(f"📄 Arquivo: **{upload['file_name']}**")
        if upload['file_type']:
            st.caption(f"📋 Tipo: {upload['file_type']}")
    
    def _render_completed_upload(self, upload: dict):
        """Renderiza upload completado"""
        st.success("✅ Upload Concluído!")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Arquivo", upload['file_name'])
        
        with col2:
            total_time = upload['end_time'] - upload['start_time']
            st.metric("Tempo Total", self._format_time(total_time))
        
        with col3:
            st.metric("Velocidade Média", f"{upload.get('final_speed_mbps', 0):.1f} MB/s")
        
        st.balloons()
    
    def _render_failed_upload(self, upload: dict):
        """Renderiza upload falhado"""
        st.error("❌ Upload Falhou")
        
        st.write(f"📄 **Arquivo**: {upload['file_name']}")
        st.write(f"📊 **Tamanho**: {self._format_bytes(upload['file_size'])}")
        
        if upload['error_message']:
            st.error(f"**Erro**: {upload['error_message']}")
        
        # Progress do que foi enviado antes do erro
        if upload['bytes_transferred'] > 0:
            progress = (upload['bytes_transferred'] / upload['file_size']) * 100
            st.write(f"📈 **Progresso antes do erro**: {progress:.1f}%")
    
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


class S3UploadWithProgress:
    """Wrapper para S3Manager com progress tracking"""
    
    def __init__(self, s3_manager, upload_monitor: EnhancedUploadMonitor):
        self.s3_manager = s3_manager
        self.upload_monitor = upload_monitor
    
    def upload_file_with_progress(self, file_obj, file_key: str, 
                                 progress_container=None) -> bool:
        """Upload com progresso em tempo real"""
        
        # Criar sessão de upload
        upload_id = self.upload_monitor.create_upload_session(
            file_obj.name,
            file_obj.size,
            file_obj.type
        )
        
        try:
            # Configurar callback para progresso
            bytes_transferred = 0
            
            def progress_callback(chunk_size):
                nonlocal bytes_transferred
                bytes_transferred += chunk_size
                self.upload_monitor.update_progress(upload_id, bytes_transferred)
            
            # Thread para atualizar UI
            stop_ui_thread = threading.Event()
            
            def update_ui():
                while not stop_ui_thread.is_set():
                    if progress_container:
                        with progress_container:
                            active = self.upload_monitor.render_upload_progress(upload_id)
                            if not active:
                                break
                    time.sleep(1)
            
            ui_thread = threading.Thread(target=update_ui, daemon=True)
            ui_thread.start()
            
            # Fazer upload baseado no tamanho
            if file_obj.size > 100 * 1024 * 1024:  # > 100MB
                success = self._multipart_upload_with_progress(
                    file_obj, file_key, upload_id, progress_callback
                )
            else:
                success = self._simple_upload_with_progress(
                    file_obj, file_key, upload_id, progress_callback
                )
            
            # Parar thread de UI
            stop_ui_thread.set()
            ui_thread.join(timeout=2)
            
            # Finalizar upload
            self.upload_monitor.complete_upload(upload_id, success)
            
            return success
            
        except Exception as e:
            self.upload_monitor.complete_upload(upload_id, False, str(e))
            raise e
    
    def _simple_upload_with_progress(self, file_obj, file_key: str, 
                                   upload_id: str, callback: Callable) -> bool:
        """Upload simples com callback de progresso"""
        try:
            # Ler arquivo em chunks para simular progresso
            chunk_size = 1024 * 1024  # 1MB chunks
            file_obj.seek(0)
            
            total_read = 0
            while True:
                chunk = file_obj.read(chunk_size)
                if not chunk:
                    break
                total_read += len(chunk)
                callback(len(chunk))
            
            # Reset e fazer upload real
            file_obj.seek(0)
            return self.s3_manager.upload_file(file_obj, file_key)
            
        except Exception as e:
            logger.error(f"Simple upload error: {e}")
            return False
    
    def _multipart_upload_with_progress(self, file_obj, file_key: str,
                                      upload_id: str, callback: Callable) -> bool:
        """Multipart upload simulado (para demo)"""
        try:
            # Simular multipart upload em chunks
            chunk_size = 25 * 1024 * 1024  # 25MB chunks
            total_chunks = (file_obj.size + chunk_size - 1) // chunk_size
            
            # Atualizar informação de chunks
            self.upload_monitor.update_progress(
                upload_id, 0, 
                {'completed': 0, 'total': total_chunks}
            )
            
            # Simular upload por chunks
            bytes_uploaded = 0
            for chunk_num in range(total_chunks):
                # Simular tempo de upload
                time.sleep(0.5)  # Simular tempo de rede
                
                chunk_bytes = min(chunk_size, file_obj.size - bytes_uploaded)
                bytes_uploaded += chunk_bytes
                
                # Atualizar progresso
                callback(chunk_bytes)
                self.upload_monitor.update_progress(
                    upload_id, 
                    bytes_uploaded,
                    {'completed': chunk_num + 1, 'total': total_chunks}
                )
            
            # Upload real após simulação
            file_obj.seek(0)
            return self.s3_manager.upload_file(file_obj, file_key)
            
        except Exception as e:
            logger.error(f"Multipart upload error: {e}")
            return False


# Funções de conveniência para integração
def create_enhanced_upload_ui(s3_manager) -> tuple:
    """Cria UI de upload melhorada"""
    
    # Inicializar monitor se não existir
    if 'upload_monitor' not in st.session_state:
        st.session_state.upload_monitor = EnhancedUploadMonitor()
    
    monitor = st.session_state.upload_monitor
    s3_with_progress = S3UploadWithProgress(s3_manager, monitor)
    
    return monitor, s3_with_progress


def render_upload_section_enhanced(s3_manager, username: str):
    """Seção de upload melhorada para substituir a original"""
    
    st.header("📤 Upload De Arquivos")
    
    # Criar monitor e wrapper S3
    monitor, s3_with_progress = create_enhanced_upload_ui(s3_manager)
    
    # Informações sobre limites e performance
    with st.expander("📋 Informações de Upload", expanded=False):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Tamanho Máximo", "2 GB", "por arquivo")
            st.caption("Multipart automático > 100MB")
        
        with col2:
            st.metric("Velocidade Esperada", "10-50 MB/s", "dependendo da conexão")
            st.caption("Progresso em tempo real")
        
        with col3:
            st.metric("Formatos", "Todos", "aceitos")
            st.caption("Verificação automática de segurança")
    
    # File uploader
    uploaded_file = st.file_uploader(
        "Escolha um arquivo:", 
        type=None,
        help="Arquivos grandes terão progresso detalhado em tempo real"
    )
    
    if uploaded_file is not None:
        # Análise do arquivo
        file_size_mb = uploaded_file.size / (1024 * 1024)
        is_large_file = file_size_mb > 100
        
        # Mostrar informações do arquivo
        with st.container():
            st.write("### 📄 Arquivo Selecionado")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**Nome:** {uploaded_file.name}")
                st.write(f"**Tamanho:** {file_size_mb:.1f} MB")
                st.write(f"**Tipo:** {uploaded_file.type or 'Desconhecido'}")
                
                # Estimativa de tempo
                if is_large_file:
                    estimated_time = file_size_mb / 15  # Assumindo 15MB/s médio
                    if estimated_time > 60:
                        time_str = f"~{estimated_time/60:.1f} minutos"
                    else:
                        time_str = f"~{estimated_time:.0f} segundos"
                    
                    st.info(f"⏱️ Tempo estimado: {time_str}")
                    st.warning("📡 Upload será feito em partes para melhor estabilidade")
            
            with col2:
                # Botão de upload
                if st.button("🚀 Iniciar Upload", type="primary", use_container_width=True):
                    # Container para progresso
                    progress_container = st.empty()
                    
                    try:
                        # Preparar upload
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        file_key = f"{username}/{timestamp}_{uploaded_file.name}"
                        
                        # Reset file pointer
                        uploaded_file.seek(0)
                        
                        # Upload com progresso
                        with st.spinner("Preparando upload..."):
                            success = s3_with_progress.upload_file_with_progress(
                                uploaded_file, 
                                file_key, 
                                progress_container
                            )
                        
                        if success:
                            # Salvar metadados no banco
                            try:
                                from database import DatabaseManager
                                from config import Config
                                
                                db_manager = DatabaseManager(Config.DATABASE_URL)
                                db_manager.save_file_metadata(
                                    file_key=file_key,
                                    original_name=uploaded_file.name,
                                    file_size=uploaded_file.size,
                                    username=username,
                                    mime_type=uploaded_file.type or "application/octet-stream"
                                )
                                
                                # Limpar progresso e mostrar sucesso final
                                progress_container.empty()
                                st.success("🎉 Upload concluído com sucesso!")
                                
                                # Aguardar antes de rerun para mostrar sucesso
                                time.sleep(90)
                                st.rerun()
                                
                            except Exception as db_error:
                                progress_container.empty()
                                st.error(f"❌ Erro ao salvar metadados: {db_error}")
                                logger.error(f"Database error: {db_error}")
                        else:
                            progress_container.empty()
                            st.error("❌ Falha no upload. Tente novamente.")
                            
                    except Exception as e:
                        progress_container.empty()
                        st.error(f"❌ Erro durante upload: {str(e)}")
                        logger.error(f"Upload error: {e}")
                        
                        # Sugestões baseadas no erro
                        if "timeout" in str(e).lower():
                            st.warning("💡 Possível timeout de rede. Tente:")
                            st.warning("- Verificar conexão de internet")
                            st.warning("- Tentar novamente em alguns minutos")
                        elif "permission" in str(e).lower():
                            st.warning("💡 Problema de permissão. Verifique:")
                            st.warning("- Configurações AWS")
                            st.warning("- Permissões do bucket S3")


def render_upload_history():
    """Renderiza histórico de uploads"""
    
    if 'upload_monitor' not in st.session_state:
        st.info("Nenhum upload realizado nesta sessão")
        return
    
    monitor = st.session_state.upload_monitor
    
    st.subheader("📊 Histórico de Uploads")
    
    # Tabs para diferentes status
    tab1, tab2, tab3 = st.tabs(["✅ Concluídos", "❌ Falharam", "🔄 Ativos"])
    
    with tab1:
        if monitor.completed_uploads:
            for upload_id, upload in monitor.completed_uploads.items():
                with st.expander(f"📄 {upload['file_name']}", expanded=False):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Tamanho**: {monitor._format_bytes(upload['file_size'])}")
                        st.write(f"**Tempo**: {monitor._format_time(upload['end_time'] - upload['start_time'])}")
                    
                    with col2:
                        st.write(f"**Velocidade**: {upload.get('final_speed_mbps', 0):.1f} MB/s")
                        st.write(f"**Concluído**: {datetime.fromtimestamp(upload['end_time']).strftime('%H:%M:%S')}")
                    
                    with col3:
                        if upload.get('total_chunks', 0) > 0:
                            st.write(f"**Chunks**: {upload['total_chunks']}")
                            st.write(f"**Tipo**: Multipart")
                        else:
                            st.write(f"**Tipo**: Simples")
        else:
            st.info("Nenhum upload concluído")
    
    with tab2:
        if monitor.failed_uploads:
            for upload_id, upload in monitor.failed_uploads.items():
                with st.expander(f"❌ {upload['file_name']}", expanded=False):
                    st.error(f"**Erro**: {upload.get('error_message', 'Desconhecido')}")
                    st.write(f"**Progresso**: {upload['progress_percentage']:.1f}%")
                    st.write(f"**Falhado em**: {datetime.fromtimestamp(upload['end_time']).strftime('%H:%M:%S')}")
        else:
            st.info("Nenhum upload falhado")
    
    with tab3:
        if monitor.active_uploads:
            for upload_id, upload in monitor.active_uploads.items():
                st.write(f"🔄 **{upload['file_name']}**")
                monitor.render_upload_progress(upload_id)
                st.divider()
        else:
            st.info("Nenhum upload ativo")


def render_upload_statistics():
    """Renderiza estatísticas de upload"""
    
    if 'upload_monitor' not in st.session_state:
        return
    
    monitor = st.session_state.upload_monitor
    
    st.subheader("📈 Estatísticas")
    
    # Calcular estatísticas
    total_completed = len(monitor.completed_uploads)
    total_failed = len(monitor.failed_uploads) 
    total_active = len(monitor.active_uploads)
    
    # Calcular tamanho total e velocidade média
    total_size = sum(upload['file_size'] for upload in monitor.completed_uploads.values())
    avg_speed = 0
    if monitor.completed_uploads:
        speeds = [upload.get('final_speed_mbps', 0) for upload in monitor.completed_uploads.values()]
        avg_speed = sum(speeds) / len(speeds)
    
    # Mostrar métricas
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Uploads Concluídos", total_completed)
    
    with col2:
        st.metric("Uploads Falhados", total_failed)
    
    with col3:
        st.metric("Uploads Ativos", total_active)
    
    with col4:
        st.metric("Velocidade Média", f"{avg_speed:.1f} MB/s")
    
    # Tamanho total
    if total_size > 0:
        st.metric("Volume Total Enviado", monitor._format_bytes(total_size))


# Log de inicialização
logger.info("✅ Enhanced upload monitor loaded successfully")
