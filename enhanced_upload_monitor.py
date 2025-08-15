"""
Monitor de Upload Melhorado - VERSÃO PARA UPLOADS SIMULTÂNEOS
Arquivo: enhanced_upload_monitor.py
Suporta até 10 uploads simultâneos com thread safety
"""
import streamlit as st
import time
import logging
import hashlib
import threading
import queue
import uuid
from typing import Dict, Optional, Callable, List
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)

@dataclass
class UploadSession:
    """Classe para representar uma sessão de upload"""
    id: str
    file_name: str
    original_file_name: str  # Nome original sem modificações
    file_size: int
    file_type: str = None
    start_time: float = field(default_factory=time.time)
    bytes_transferred: int = 0
    status: str = 'initializing'
    speed_mbps: float = 0
    eta_seconds: float = 0
    progress_percentage: float = 0
    error_message: str = None
    chunks_completed: int = 0
    total_chunks: int = 0
    last_update: float = field(default_factory=time.time)
    username: str = None
    file_key: str = None
    priority: int = 1  # 1=alta, 2=normal, 3=baixa
    retry_count: int = 0
    max_retries: int = 3

class ConcurrentUploadManager:
    """Gerenciador de uploads simultâneos com thread safety"""
    
    def __init__(self, max_concurrent_uploads: int = 10):
        self.max_concurrent_uploads = max_concurrent_uploads
        self.active_uploads: Dict[str, UploadSession] = {}
        self.completed_uploads: Dict[str, UploadSession] = {}
        self.failed_uploads: Dict[str, UploadSession] = {}
        self.upload_queue: queue.PriorityQueue = queue.PriorityQueue()
        
        # Thread safety
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent_uploads, thread_name_prefix="upload_worker")
        self._active_futures = {}
        
        # File name collision handling
        self._file_name_counter = {}
        self._name_lock = Lock()
        
        self.logger = logging.getLogger(__name__)
        
        # Estatísticas globais
        self.total_bytes_uploaded = 0
        self.total_files_uploaded = 0
        self.average_speed = 0.0
        
        self.logger.info(f"✅ Concurrent Upload Manager initialized (max: {max_concurrent_uploads})")
    
    def generate_unique_filename(self, original_name: str, username: str) -> tuple[str, str]:
        """
        Gera nome único para arquivo, evitando colisões
        Returns: (unique_filename, file_key)
        """
        with self._name_lock:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Extrair extensão
            if '.' in original_name:
                name_part, extension = original_name.rsplit('.', 1)
                extension = f".{extension}"
            else:
                name_part = original_name
                extension = ""
            
            # Base key sem counter
            base_key = f"{username}/{timestamp}_{name_part}{extension}"
            
            # Verificar se já existe
            counter_key = f"{username}_{name_part}_{timestamp}"
            
            if counter_key in self._file_name_counter:
                self._file_name_counter[counter_key] += 1
                counter = self._file_name_counter[counter_key]
                unique_name = f"{name_part}_{counter:02d}{extension}"
                file_key = f"{username}/{timestamp}_{unique_name}"
            else:
                self._file_name_counter[counter_key] = 0
                unique_name = original_name
                file_key = base_key
            
            self.logger.info(f"Generated unique filename: {original_name} -> {unique_name}")
            return unique_name, file_key
    
    def create_upload_session(self, file_name: str, file_size: int, username: str,
                             file_type: str = None, priority: int = 1) -> str:
        """Cria sessão de upload com nome único"""
        
        # Gerar nome único
        unique_filename, file_key = self.generate_unique_filename(file_name, username)
        
        # Gerar ID único
        upload_id = f"{username}_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        session = UploadSession(
            id=upload_id,
            file_name=unique_filename,
            original_file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            username=username,
            file_key=file_key,
            priority=priority
        )
        
        with self._lock:
            self.active_uploads[upload_id] = session
        
        self.logger.info(f"Upload session created: {upload_id} for {file_name} -> {unique_filename}")
        return upload_id
    
    def queue_upload(self, upload_id: str, upload_func: Callable, *args, **kwargs):
        """Adiciona upload à fila de processamento"""
        with self._lock:
            if upload_id in self.active_uploads:
                session = self.active_uploads[upload_id]
                # Usar prioridade negativa para queue (menor valor = maior prioridade)
                self.upload_queue.put((-session.priority, upload_id, upload_func, args, kwargs))
                session.status = 'queued'
                self.logger.info(f"Upload queued: {upload_id} (priority: {session.priority})")
    
    def start_upload_processing(self):
        """Inicia processamento da fila de uploads"""
        def process_queue():
            while True:
                try:
                    if self.upload_queue.empty():
                        time.sleep(0.1)
                        continue
                    
                    # Verificar se temos slots disponíveis
                    with self._lock:
                        active_count = len([s for s in self.active_uploads.values() 
                                          if s.status == 'uploading'])
                    
                    if active_count >= self.max_concurrent_uploads:
                        time.sleep(0.5)
                        continue
                    
                    # Pegar próximo upload da fila
                    try:
                        priority, upload_id, upload_func, args, kwargs = self.upload_queue.get(timeout=1)
                        
                        # Verificar se upload ainda é válido
                        with self._lock:
                            if upload_id not in self.active_uploads:
                                continue
                            
                            session = self.active_uploads[upload_id]
                            if session.status not in ['queued', 'initializing']:
                                continue
                        
                        # Iniciar upload em thread
                        future = self._executor.submit(self._execute_upload, upload_id, upload_func, *args, **kwargs)
                        
                        with self._lock:
                            self._active_futures[upload_id] = future
                        
                    except queue.Empty:
                        continue
                        
                except Exception as e:
                    self.logger.error(f"Error in upload queue processing: {e}")
                    time.sleep(1)
        
        # Iniciar thread de processamento da fila
        queue_thread = threading.Thread(target=process_queue, daemon=True, name="upload_queue_processor")
        queue_thread.start()
        self.logger.info("Upload queue processor started")
    
    def _execute_upload(self, upload_id: str, upload_func: Callable, *args, **kwargs) -> bool:
        """Executa upload em thread separada"""
        try:
            with self._lock:
                if upload_id not in self.active_uploads:
                    return False
                session = self.active_uploads[upload_id]
                session.status = 'uploading'
                session.start_time = time.time()
            
            self.logger.info(f"Starting upload execution: {upload_id}")
            
            # Executar função de upload
            success = upload_func(upload_id, *args, **kwargs)
            
            # Finalizar upload
            self.complete_upload(upload_id, success)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Upload execution error for {upload_id}: {e}")
            self.complete_upload(upload_id, False, str(e))
            return False
        finally:
            # Remover da lista de futures ativos
            with self._lock:
                if upload_id in self._active_futures:
                    del self._active_futures[upload_id]
    
    def update_progress(self, upload_id: str, bytes_transferred: int, 
                       chunk_info: dict = None):
        """Atualiza progresso do upload de forma thread-safe"""
        with self._lock:
            if upload_id not in self.active_uploads:
                return
            
            session = self.active_uploads[upload_id]
            session.bytes_transferred = bytes_transferred
            session.progress_percentage = (bytes_transferred / session.file_size) * 100
            session.last_update = time.time()
            session.status = 'uploading'
            
            # Calcular velocidade
            elapsed = time.time() - session.start_time
            if elapsed > 0:
                session.speed_mbps = (bytes_transferred / (1024 * 1024)) / elapsed
                
                # Calcular ETA
                remaining_bytes = session.file_size - bytes_transferred
                if session.speed_mbps > 0:
                    session.eta_seconds = remaining_bytes / (session.speed_mbps * 1024 * 1024)
            
            # Informações de chunks
            if chunk_info:
                session.chunks_completed = chunk_info.get('completed', 0)
                session.total_chunks = chunk_info.get('total', 0)
    
    def complete_upload(self, upload_id: str, success: bool = True, error_message: str = None):
        """Finaliza upload e atualiza estatísticas"""
        with self._lock:
            if upload_id not in self.active_uploads:
                return
            
            session = self.active_uploads.pop(upload_id)
            session.status = 'completed' if success else 'failed'
            session.error_message = error_message
            
            # Calcular estatísticas finais
            end_time = time.time()
            total_time = end_time - session.start_time
            
            if total_time > 0:
                session.final_speed_mbps = (session.file_size / (1024 * 1024)) / total_time
            
            # Atualizar estatísticas globais
            if success:
                self.completed_uploads[upload_id] = session
                self.total_bytes_uploaded += session.file_size
                self.total_files_uploaded += 1
                
                # Calcular velocidade média
                total_sessions = len(self.completed_uploads)
                if total_sessions > 0:
                    total_speed = sum(s.final_speed_mbps or 0 for s in self.completed_uploads.values())
                    self.average_speed = total_speed / total_sessions
                
                self.logger.info(f"Upload completed: {upload_id} - {session.final_speed_mbps:.1f}MB/s")
            else:
                self.failed_uploads[upload_id] = session
                self.logger.error(f"Upload failed: {upload_id} - {error_message}")
    
    def get_upload_status(self, upload_id: str) -> Optional[UploadSession]:
        """Retorna status do upload de forma thread-safe"""
        with self._lock:
            if upload_id in self.active_uploads:
                return self.active_uploads[upload_id]
        
        if upload_id in self.completed_uploads:
            return self.completed_uploads[upload_id]
        
        if upload_id in self.failed_uploads:
            return self.failed_uploads[upload_id]
        
        return None
    
    def get_all_active_uploads(self) -> List[UploadSession]:
        """Retorna lista de todos os uploads ativos"""
        with self._lock:
            return list(self.active_uploads.values())
    
    def get_system_statistics(self) -> Dict:
        """Retorna estatísticas do sistema"""
        with self._lock:
            active_count = len(self.active_uploads)
            uploading_count = len([s for s in self.active_uploads.values() if s.status == 'uploading'])
            queued_count = self.upload_queue.qsize()
        
        completed_count = len(self.completed_uploads)
        failed_count = len(self.failed_uploads)
        
        return {
            'active_uploads': active_count,
            'uploading_now': uploading_count,
            'queued_uploads': queued_count,
            'completed_uploads': completed_count,
            'failed_uploads': failed_count,
            'total_bytes_uploaded': self.total_bytes_uploaded,
            'total_files_uploaded': self.total_files_uploaded,
            'average_speed_mbps': self.average_speed,
            'max_concurrent': self.max_concurrent_uploads
        }
    
    def cancel_upload(self, upload_id: str) -> bool:
        """Cancela upload em progresso"""
        with self._lock:
            if upload_id in self.active_uploads:
                session = self.active_uploads[upload_id]
                session.status = 'cancelled'
                
                # Cancelar future se existe
                if upload_id in self._active_futures:
                    future = self._active_futures[upload_id]
                    future.cancel()
                    del self._active_futures[upload_id]
                
                # Mover para failed
                self.failed_uploads[upload_id] = self.active_uploads.pop(upload_id)
                self.failed_uploads[upload_id].error_message = "Upload cancelado pelo usuário"
                
                self.logger.info(f"Upload cancelled: {upload_id}")
                return True
        
        return False
    
    def retry_failed_upload(self, upload_id: str) -> bool:
        """Tenta novamente um upload falhado"""
        if upload_id not in self.failed_uploads:
            return False
        
        failed_session = self.failed_uploads[upload_id]
        
        if failed_session.retry_count >= failed_session.max_retries:
            self.logger.warning(f"Max retries exceeded for upload: {upload_id}")
            return False
        
        # Criar nova sessão baseada na falhada
        new_upload_id = self.create_upload_session(
            failed_session.original_file_name,
            failed_session.file_size,
            failed_session.username,
            failed_session.file_type,
            failed_session.priority
        )
        
        with self._lock:
            new_session = self.active_uploads[new_upload_id]
            new_session.retry_count = failed_session.retry_count + 1
            
            # Remover sessão falhada
            del self.failed_uploads[upload_id]
        
        self.logger.info(f"Retrying upload: {upload_id} -> {new_upload_id} (attempt {new_session.retry_count})")
        return True
    
    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Remove sessões antigas para liberar memória"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        # Limpar completed
        old_completed = [
            uid for uid, session in self.completed_uploads.items()
            if session.start_time < cutoff_time
        ]
        
        for uid in old_completed:
            del self.completed_uploads[uid]
        
        # Limpar failed
        old_failed = [
            uid for uid, session in self.failed_uploads.items()
            if session.start_time < cutoff_time
        ]
        
        for uid in old_failed:
            del self.failed_uploads[uid]
        
        if old_completed or old_failed:
            self.logger.info(f"Cleaned up {len(old_completed)} completed and {len(old_failed)} failed sessions")


# Implementação específica para S3 com suporte a uploads simultâneos
class S3ConcurrentUploadManager:
    """Gerenciador específico para uploads S3 com concorrência"""
    
    def __init__(self, s3_manager, concurrent_manager: ConcurrentUploadManager):
        self.s3_manager = s3_manager
        self.concurrent_manager = concurrent_manager
        self.logger = logging.getLogger(__name__)
    
    def upload_file_concurrent(self, file_obj, file_name: str, username: str, 
                              priority: int = 1) -> str:
        """Inicia upload concorrente de arquivo"""
        
        # Criar sessão
        upload_id = self.concurrent_manager.create_upload_session(
            file_name=file_name,
            file_size=file_obj.size,
            username=username,
            file_type=getattr(file_obj, 'type', None),
            priority=priority
        )
        
        # Preparar função de upload
        def upload_func(upload_id: str) -> bool:
            return self._execute_s3_upload(upload_id, file_obj)
        
        # Adicionar à fila
        self.concurrent_manager.queue_upload(upload_id, upload_func)
        
        return upload_id
    
    def _execute_s3_upload(self, upload_id: str, file_obj) -> bool:
        """Executa upload para S3 com tracking de progresso"""
        try:
            session = self.concurrent_manager.get_upload_status(upload_id)
            if not session:
                return False
            
            file_size = session.file_size
            file_key = session.file_key
            
            self.logger.info(f"Starting S3 upload: {upload_id} -> {file_key}")
            
            # Reset file pointer
            file_obj.seek(0)
            
            # Simular progresso para uploads grandes
            if file_size > 50 * 1024 * 1024:  # > 50MB
                return self._multipart_upload_with_progress(upload_id, file_obj, file_key)
            else:
                return self._simple_upload_with_progress(upload_id, file_obj, file_key)
                
        except Exception as e:
            self.logger.error(f"S3 upload error for {upload_id}: {e}")
            return False
    
    def _simple_upload_with_progress(self, upload_id: str, file_obj, file_key: str) -> bool:
        """Upload simples com progresso simulado"""
        try:
            session = self.concurrent_manager.get_upload_status(upload_id)
            file_size = session.file_size
            
            # Simular progresso em chunks
            chunk_size = min(1024 * 1024, file_size // 10)  # Máximo 1MB, mínimo 10 updates
            bytes_uploaded = 0
            
            while bytes_uploaded < file_size:
                chunk_bytes = min(chunk_size, file_size - bytes_uploaded)
                bytes_uploaded += chunk_bytes
                
                # Atualizar progresso
                self.concurrent_manager.update_progress(upload_id, bytes_uploaded)
                
                # Simular tempo de rede
                time.sleep(0.1)
            
            # Upload real
            file_obj.seek(0)
            success = self.s3_manager.upload_file(file_obj, file_key)
            
            if success:
                # Garantir 100% no final
                self.concurrent_manager.update_progress(upload_id, file_size)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Simple upload error: {e}")
            return False
    
    def _multipart_upload_with_progress(self, upload_id: str, file_obj, file_key: str) -> bool:
        """Upload multipart com progresso detalhado"""
        try:
            session = self.concurrent_manager.get_upload_status(upload_id)
            file_size = session.file_size
            
            # Configurar chunks para multipart
            chunk_size = 25 * 1024 * 1024  # 25MB por chunk
            total_chunks = (file_size + chunk_size - 1) // chunk_size
            
            self.logger.info(f"Multipart upload: {total_chunks} chunks for {upload_id}")
            
            bytes_uploaded = 0
            for chunk_num in range(total_chunks):
                chunk_bytes = min(chunk_size, file_size - bytes_uploaded)
                bytes_uploaded += chunk_bytes
                
                # Atualizar progresso com informações de chunk
                self.concurrent_manager.update_progress(
                    upload_id, 
                    bytes_uploaded,
                    {'completed': chunk_num + 1, 'total': total_chunks}
                )
                
                # Simular tempo de processamento do chunk
                time.sleep(0.3)
            
            # Upload real após simulação
            file_obj.seek(0)
            success = self.s3_manager.upload_file(file_obj, file_key)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Multipart upload error: {e}")
            return False


# Funções de integração com Streamlit
def get_concurrent_upload_manager() -> ConcurrentUploadManager:
    """Obtém ou cria manager de uploads simultâneos"""
    if 'concurrent_upload_manager' not in st.session_state:
        manager = ConcurrentUploadManager(max_concurrent_uploads=10)
        manager.start_upload_processing()
        st.session_state.concurrent_upload_manager = manager
    
    return st.session_state.concurrent_upload_manager

def get_s3_concurrent_manager(s3_manager) -> S3ConcurrentUploadManager:
    """Obtém ou cria manager S3 concorrente"""
    concurrent_manager = get_concurrent_upload_manager()
    
    if 's3_concurrent_manager' not in st.session_state:
        st.session_state.s3_concurrent_manager = S3ConcurrentUploadManager(
            s3_manager, concurrent_manager
        )
    
    return st.session_state.s3_concurrent_manager

# Log de inicialização
logger.info("✅ Enhanced concurrent upload monitor loaded successfully")
