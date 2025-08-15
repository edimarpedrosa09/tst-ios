"""
Teste do Sistema de Uploads Simultâneos
Arquivo: test_concurrent_uploads.py
"""
import unittest
import time
import tempfile
import os
from unittest.mock import Mock, patch
from enhanced_upload_monitor import ConcurrentUploadManager, UploadSession

class TestConcurrentUploads(unittest.TestCase):
    """Testes para o sistema de uploads simultâneos"""
    
    def setUp(self):
        """Setup para cada teste"""
        self.manager = ConcurrentUploadManager(max_concurrent_uploads=3)
        self.test_username = "test_user"
    
    def test_generate_unique_filename(self):
        """Testa geração de nomes únicos"""
        # Primeiro arquivo
        name1, key1 = self.manager.generate_unique_filename("test.pdf", self.test_username)
        self.assertEqual(name1, "test.pdf")
        self.assertIn(self.test_username, key1)
        
        # Segundo arquivo com mesmo nome
        name2, key2 = self.manager.generate_unique_filename("test.pdf", self.test_username)
        self.assertEqual(name2, "test_01.pdf")
        self.assertNotEqual(key1, key2)
        
        # Terceiro arquivo
        name3, key3 = self.manager.generate_unique_filename("test.pdf", self.test_username)
        self.assertEqual(name3, "test_02.pdf")
    
    def test_create_upload_session(self):
        """Testa criação de sessão de upload"""
        upload_id = self.manager.create_upload_session(
            file_name="test.pdf",
            file_size=1024,
            username=self.test_username,
            file_type="application/pdf",
            priority=1
        )
        
        self.assertIsNotNone(upload_id)
        self.assertIn(upload_id, self.manager.active_uploads)
        
        session = self.manager.get_upload_status(upload_id)
        self.assertIsNotNone(session)
        self.assertEqual(session.original_file_name, "test.pdf")
        self.assertEqual(session.file_size, 1024)
        self.assertEqual(session.username, self.test_username)
        self.assertEqual(session.priority, 1)
    
    def test_update_progress(self):
        """Testa atualização de progresso"""
        upload_id = self.manager.create_upload_session(
            file_name="test.pdf",
            file_size=1000,
            username=self.test_username
        )
        
        # Atualizar progresso para 50%
        self.manager.update_progress(upload_id, 500)
        
        session = self.manager.get_upload_status(upload_id)
        self.assertEqual(session.bytes_transferred, 500)
        self.assertEqual(session.progress_percentage, 50.0)
        self.assertEqual(session.status, 'uploading')
    
    def test_complete_upload(self):
        """Testa finalização de upload"""
        upload_id = self.manager.create_upload_session(
            file_name="test.pdf",
            file_size=1000,
            username=self.test_username
        )
        
        # Completar com sucesso
        self.manager.complete_upload(upload_id, success=True)
        
        # Verificar se foi movido para completed
        self.assertNotIn(upload_id, self.manager.active_uploads)
        self.assertIn(upload_id, self.manager.completed_uploads)
        
        session = self.manager.get_upload_status(upload_id)
        self.assertEqual(session.status, 'completed')
    
    def test_complete_upload_with_error(self):
        """Testa finalização de upload com erro"""
        upload_id = self.manager.create_upload_session(
            file_name="test.pdf",
            file_size=1000,
            username=self.test_username
        )
        
        # Completar com erro
        error_msg = "Network timeout"
        self.manager.complete_upload(upload_id, success=False, error_message=error_msg)
        
        # Verificar se foi movido para failed
        self.assertNotIn(upload_id, self.manager.active_uploads)
        self.assertIn(upload_id, self.manager.failed_uploads)
        
        session = self.manager.get_upload_status(upload_id)
        self.assertEqual(session.status, 'failed')
        self.assertEqual(session.error_message, error_msg)
    
    def test_cancel_upload(self):
        """Testa cancelamento de upload"""
        upload_id = self.manager.create_upload_session(
            file_name="test.pdf",
            file_size=1000,
            username=self.test_username
        )
        
        # Cancelar upload
        success = self.manager.cancel_upload(upload_id)
        
        self.assertTrue(success)
        self.assertNotIn(upload_id, self.manager.active_uploads)
        self.assertIn(upload_id, self.manager.failed_uploads)
        
        session = self.manager.get_upload_status(upload_id)
        self.assertEqual(session.status, 'cancelled')
    
    def test_get_system_statistics(self):
        """Testa estatísticas do sistema"""
        # Criar algumas sessões
        id1 = self.manager.create_upload_session("file1.pdf", 1000, self.test_username)
        id2 = self.manager.create_upload_session("file2.pdf", 2000, self.test_username)
        
        # Completar uma
        self.manager.complete_upload(id1, success=True)
        
        # Falhar outra
        self.manager.complete_upload(id2, success=False, error_message="Test error")
        
        stats = self.manager.get_system_statistics()
        
        self.assertEqual(stats['completed_uploads'], 1)
        self.assertEqual(stats['failed_uploads'], 1)
        self.assertEqual(stats['active_uploads'], 0)
        self.assertEqual(stats['max_concurrent'], 3)
    
    def test_thread_safety(self):
        """Testa thread safety básico"""
        import threading
        
        results = []
        
        def create_sessions():
            for i in range(10):
                upload_id = self.manager.create_upload_session(
                    file_name=f"file_{i}.pdf",
                    file_size=1000,
                    username=self.test_username
                )
                results.append(upload_id)
                time.sleep(0.01)  # Simular algum processamento
        
        # Criar múltiplas threads
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=create_sessions)
            threads.append(thread)
            thread.start()
        
        # Aguardar conclusão
        for thread in threads:
            thread.join()
        
        # Verificar que todas as sessões foram criadas
        self.assertEqual(len(results), 30)
        self.assertEqual(len(set(results)), 30)  # Todos IDs únicos
        
        # Verificar que todas estão no manager
        for upload_id in results:
            self.assertIn(upload_id, self.manager.active_uploads)


class TestFileNameGeneration(unittest.TestCase):
    """Testes específicos para geração de nomes únicos"""
    
    def setUp(self):
        self.manager = ConcurrentUploadManager()
    
    def test_simple_filename(self):
        """Testa arquivo simples"""
        name, key = self.manager.generate_unique_filename("document.pdf", "user1")
        self.assertEqual(name, "document.pdf")
        self.assertIn("user1", key)
        self.assertIn("document.pdf", key)
    
    def test_filename_without_extension(self):
        """Testa arquivo sem extensão"""
        name, key = self.manager.generate_unique_filename("README", "user1")
        self.assertEqual(name, "README")
    
    def test_filename_with_multiple_dots(self):
        """Testa arquivo com múltiplos pontos"""
        name, key = self.manager.generate_unique_filename("file.backup.tar.gz", "user1")
        self.assertEqual(name, "file.backup.tar.gz")
    
    def test_special_characters(self):
        """Testa caracteres especiais no nome"""
        name, key = self.manager.generate_unique_filename("file (1).pdf", "user1")
        self.assertEqual(name, "file (1).pdf")
    
    def test_collision_handling(self):
        """Testa resolução de colisões de nomes"""
        # Simular colisão forçando mesmo timestamp
        original_time = time.time()
        
        with patch('time.time', return_value=original_time):
            with patch('datetime.datetime') as mock_datetime:
                mock_datetime.now.return_value.strftime.return_value = "20241201_120000"
                
                # Primeiro arquivo
                name1, key1 = self.manager.generate_unique_filename("test.pdf", "user1")
                
                # Simular que já existe um contador
                self.manager._file_name_counter[f"user1_test_20241201_120000"] = 0
                
                # Segundo arquivo
                name2, key2 = self.manager.generate_unique_filename("test.pdf", "user1")
                
                self.assertEqual(name1, "test.pdf")
                self.assertEqual(name2, "test_01.pdf")
                self.assertNotEqual(key1, key2)


def run_performance_test():
    """Teste de performance para uploads simultâneos"""
    print("=== Teste de Performance ===")
    
    manager = ConcurrentUploadManager(max_concurrent_uploads=10)
    
    # Criar 50 sessões de upload
    start_time = time.time()
    upload_ids = []
    
    for i in range(50):
        upload_id = manager.create_upload_session(
            file_name=f"performance_test_{i}.pdf",
            file_size=1024 * 1024,  # 1MB
            username="perf_user",
            priority=2
        )
        upload_ids.append(upload_id)
    
    creation_time = time.time() - start_time
    print(f"Criação de 50 sessões: {creation_time:.3f}s")
    
    # Simular progresso em todas
    start_time = time.time()
    for upload_id in upload_ids:
        for progress in [25, 50, 75, 100]:
            manager.update_progress(upload_id, (1024 * 1024 * progress) // 100)
    
    progress_time = time.time() - start_time
    print(f"Atualização de progresso (200 updates): {progress_time:.3f}s")
    
    # Finalizar todas
    start_time = time.time()
    for i, upload_id in enumerate(upload_ids):
        success = i % 10 != 0  # 10% de falhas
        manager.complete_upload(upload_id, success=success, 
                              error_message="Test error" if not success else None)
    
    completion_time = time.time() - start_time
    print(f"Finalização de 50 uploads: {completion_time:.3f}s")
    
    # Estatísticas finais
    stats = manager.get_system_statistics()
    print(f"Estatísticas finais: {stats}")
    
    # Cleanup
    manager.cleanup_old_sessions(max_age_hours=0)
    print("Cleanup concluído")


if __name__ == "__main__":
    # Executar testes unitários
    print("=== Executando Testes Unitários ===")
    unittest.main(verbosity=2, exit=False)
    
    print("\n")
    
    # Executar teste de performance
    run_performance_test()
    
    print("\n=== Todos os Testes Concluídos ===")
