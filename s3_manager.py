"""
Módulo S3Manager - VERSÃO SEGURA COM VALIDAÇÃO DE BLACKLIST
Implementa bloqueio efetivo de extensões perigosas sem dependências externas
ACEITA QUALQUER NOME DE ARQUIVO (exceto extensões perigosas)
CORRIGIDO: Metadata S3 com apenas caracteres ASCII
"""
import boto3
import logging
import os
import re
import hashlib
import unicodedata
import base64
import urllib.parse
from botocore.exceptions import ClientError
from typing import Optional, Tuple, Set, Dict, Any, List
from pathlib import Path
import mimetypes
import secrets
from datetime import datetime

logger = logging.getLogger(__name__)

class FileValidationError(Exception):
    """Exceção para erros de validação de arquivo"""
    pass

class BlacklistValidationError(Exception):
    """Exceção específica para arquivos bloqueados por blacklist"""
    pass

def make_ascii_safe(text: str) -> str:
    """Converte string para formato seguro para metadata S3"""
    if not text:
        return ""
    
    # Mapeamento de caracteres acentuados para ASCII
    replacements = {
        'Ç': 'C', 'ç': 'c',
        'Ã': 'A', 'ã': 'a', 'Á': 'A', 'á': 'a', 'À': 'A', 'à': 'a', 'Â': 'A', 'â': 'a', 'Ä': 'A', 'ä': 'a',
        'É': 'E', 'é': 'e', 'Ê': 'E', 'ê': 'e', 'È': 'E', 'è': 'e', 'Ë': 'E', 'ë': 'e',
        'Í': 'I', 'í': 'i', 'Ì': 'I', 'ì': 'i', 'Î': 'I', 'î': 'i', 'Ï': 'I', 'ï': 'i',
        'Ó': 'O', 'ó': 'o', 'Õ': 'O', 'õ': 'o', 'Ô': 'O', 'ô': 'o', 'Ò': 'O', 'ò': 'o', 'Ö': 'O', 'ö': 'o',
        'Ú': 'U', 'ú': 'u', 'Ù': 'U', 'ù': 'u', 'Û': 'U', 'û': 'u', 'Ü': 'U', 'ü': 'u',
        'Ñ': 'N', 'ñ': 'n',
        '°': 'o', 'º': 'o', 'ª': 'a'
    }
    
    ascii_text = ""
    for char in text:
        if ord(char) < 128:  # É ASCII
            ascii_text += char
        elif char in replacements:
            ascii_text += replacements[char]
        else:
            ascii_text += '_'  # Substituir outros caracteres não-ASCII
    
    return ascii_text

class FileNameSanitizer:
    """Classe para sanitização segura de nomes de arquivo com BLACKLIST EFETIVA"""

    # ============= BLACKLIST DE EXTENSÕES PERIGOSAS =============
    # ESTA É A LISTA QUE SERÁ EFETIVAMENTE VERIFICADA
    BLOCKED_EXTENSIONS: Set[str] = {
        # Executáveis Windows
        'exe', 'dll', 'com', 'bat', 'cmd', 'scr', 'msi', 'vbs', 'vbe',
        'js', 'jse', 'ws', 'wsf', 'wsc', 'wsh', 'ps1', 'ps1xml', 'ps2',
        'ps2xml', 'psc1', 'psc2', 'msh', 'msh1', 'msh2', 'mshxml', 'msh1xml',
        'msh2xml', 'scf', 'lnk', 'inf', 'reg', 'gadget', 'application',
        'msc', 'msp', 'hta', 'cpl', 'jar', 'cab', 'hlp', 'chm',
        
        # Executáveis Unix/Linux
        'sh', 'bash', 'csh', 'tcsh', 'ksh', 'zsh', 'fish', 'bin', 'run',
        'elf', 'deb', 'rpm', 'dmg', 'pkg', 'app', 'appimage', 'snap',
        
        # Executáveis macOS
        'command', 'action', 'workflow', 'applescript', 'scpt', 'scptd',
        'osa', 'osax', 'dylib', 'so',
        
        # Scripts e automação
        'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw', 'rb', 'rbw',
        'pl', 'pm', 'cgi', 'fcgi', 'php', 'php3', 'php4', 'php5', 'php7',
        'phtml', 'asp', 'aspx', 'cer', 'jsp', 'jspx',
        
        # Documentos com macros
        'docm', 'xlsm', 'pptm', 'xlam', 'ppsm', 'sldm', 'dotm', 'xltm',
        'potm', 'ppam',
        
        # Outros potencialmente perigosos
        'iso', 'img', 'vhd', 'vhdx', 'vmdk', 'ova', 'ovf',
        'url', 'website', 'partial', 'crdownload',
        'air', 'appx', 'appxbundle', 'deskthemepack', 'diagcab',
        'diagcfg', 'diagpkg', 'drv', 'efi', 'fon', 'grp', 'ime',
        'job', 'library-ms', 'mdu', 'msu', 'ops', 'pal', 'pcd',
        'pif', 'prf', 'prg', 'pst', 'pvk', 'pwl', 'qds', 'rdp',
        'rem', 'rgu', 'rom', 'rsp', 'sct', 'sfx', 'shb', 'shs',
        'sys', 'theme', 'themepack', 'udl', 'vb', 'vbscript', 'vxd',
        'webpnp', 'xbap', 'xll', 'xnk'
    }
    
    # Arquivos permitidos explicitamente
    ALLOWED_ARCHIVES = {
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'tgz'
    }
    
    # Magic bytes para detecção básica
    MAGIC_BYTES = {
        # Executáveis
        b'MZ': 'exe/dll',  # Windows PE
        b'\x7fELF': 'elf',  # Linux ELF
        b'#!': 'script',  # Shell script
        b'#!/': 'script',  # Shell script
        b'\xca\xfe\xba\xbe': 'macho',  # macOS Mach-O
        b'\xce\xfa\xed\xfe': 'macho',  # macOS Mach-O
        b'\xcf\xfa\xed\xfe': 'macho',  # macOS Mach-O
        
        # Documentos
        b'%PDF': 'pdf',
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'ole',  # MS Office
        
        # Scripts
        b'<?php': 'php',
        b'<?PHP': 'php',
        b'<%': 'asp',
    }

    # Nomes reservados do sistema Windows
    RESERVED_NAMES = [
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
        'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
        'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9', 'CLOCK$', 'CONFIG$'
    ]

    @staticmethod
    def extract_all_extensions(filename: str) -> Tuple[str, List[str]]:
        """
        Extrai TODAS as extensões de um arquivo
        Exemplo: file.tar.gz -> ('file', ['tar', 'gz'])
        """
        if not filename:
            return '', []
        
        # Separar por pontos
        parts = filename.split('.')
        
        if len(parts) == 1:
            return filename, []
        
        # Nome base é a primeira parte
        base_name = parts[0]
        
        # Todas as outras partes são extensões
        extensions = [ext.lower() for ext in parts[1:] if ext]
        
        return base_name, extensions

    @staticmethod
    def check_blacklist(filename: str) -> Tuple[bool, str]:
        """
        Verifica se o arquivo está na blacklist
        
        Returns:
            Tuple[está_bloqueado, motivo]
        """
        base_name, extensions = FileNameSanitizer.extract_all_extensions(filename)
        
        # Verificar CADA extensão
        for ext in extensions:
            if ext in FileNameSanitizer.BLOCKED_EXTENSIONS:
                logger.warning(f"BLOCKED: File '{filename}' has blacklisted extension: .{ext}")
                return True, f"Extensão .{ext} não é permitida por questões de segurança"
        
        # Verificar duplas extensões comuns de bypass APENAS para executáveis
        if len(extensions) >= 2:
            dangerous_first = extensions[0] in FileNameSanitizer.BLOCKED_EXTENSIONS
            safe_compression = all(ext in FileNameSanitizer.ALLOWED_ARCHIVES or ext in ['tar'] for ext in extensions)
            
            if dangerous_first and not safe_compression:
                logger.warning(f"BLOCKED: Double extension bypass attempt: {filename}")
                return True, f"Arquivos com múltiplas extensões suspeitas não são permitidos"
        
        # Verificar nomes reservados (apenas o nome base, sem path)
        base_name_only = os.path.basename(base_name)
        if base_name_only.upper() in FileNameSanitizer.RESERVED_NAMES:
            logger.warning(f"BLOCKED: Reserved system name: {base_name_only}")
            return True, f"Nome '{base_name_only}' é reservado pelo sistema"
        
        return False, ""

    @staticmethod
    def check_magic_bytes(file_content: bytes) -> Tuple[bool, str]:
        """
        Verifica os magic bytes do arquivo para detectar tipos perigosos
        NÃO bloqueia ZIPs normais, apenas JARs
        
        Returns:
            Tuple[é_perigoso, tipo_detectado]
        """
        if not file_content or len(file_content) < 4:
            return False, "unknown"
        
        # Verificar primeiros bytes
        for magic, file_type in FileNameSanitizer.MAGIC_BYTES.items():
            if file_content.startswith(magic):
                # Tipos sempre perigosos
                if file_type in ['exe/dll', 'elf', 'script', 'macho', 'php', 'asp']:
                    logger.warning(f"BLOCKED: Dangerous file type detected by magic bytes: {file_type}")
                    return True, file_type
                
                return False, file_type
        
        # Verificar se é um JAR (ZIP com estrutura Java)
        if file_content.startswith(b'PK'):
            # Verificar se é JAR verificando a presença de arquivos Java
            if b'META-INF/' in file_content[:1024] or b'.class' in file_content[:1024]:
                logger.warning("BLOCKED: JAR file detected (Java archive)")
                return True, 'jar'
            # Caso contrário, é um ZIP normal - permitir
            logger.debug("ALLOWED: Regular ZIP file detected")
            return False, 'zip'
        
        # Verificar padrões em texto para scripts
        text_start = file_content[:1024].lower()
        
        # Detectar scripts por conteúdo
        script_patterns = [
            b'#!/bin/',
            b'#! /bin/',
            b'#!/usr/bin/',
            b'#! /usr/bin/',
            b'@echo off',
            b'@echo on',
            b'powershell',
            b'<?php',
            b'<%@',
        ]
        
        for pattern in script_patterns:
            if pattern in text_start:
                logger.warning(f"BLOCKED: Script pattern detected: {pattern[:20]}")
                return True, "script"
        
        return False, "unknown"

    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 255) -> Tuple[str, bool]:
        """
        Sanitiza nome de arquivo - VERSÃO ULTRA PERMISSIVA
        PRESERVA TODOS OS CARACTERES POSSÍVEIS
        
        Returns:
            Tuple[nome_sanitizado, passou_validação]
        """
        if not filename:
            return "unnamed_file", False

        # PRIMEIRO: Verificar blacklist ANTES de sanitizar
        is_blocked, block_reason = FileNameSanitizer.check_blacklist(filename)
        if is_blocked:
            raise BlacklistValidationError(block_reason)

        # MÍNIMA SANITIZAÇÃO - apenas o absolutamente necessário
        
        # Remover apenas caracteres de controle perigosos (null bytes, etc)
        filename = filename.replace('\x00', '')  # Null byte
        
        # Remover path traversal
        if '..' in filename:
            filename = filename.replace('..', '')
        
        # Se o nome começa com / ou \, pegar apenas o nome base
        if filename.startswith('/') or filename.startswith('\\'):
            filename = os.path.basename(filename)
        
        # Remover qualquer path e pegar apenas o nome do arquivo
        filename = os.path.basename(filename)
        
        # NÃO MODIFICAR MAIS NADA - preservar o nome original ao máximo
        
        # Apenas verificar comprimento
        if len(filename) > max_length:
            # Preservar extensão se houver
            parts = filename.rsplit('.', 1)
            if len(parts) == 2:
                base_name, extension = parts
                max_base = max_length - len(extension) - 1
                filename = base_name[:max_base] + '.' + extension
            else:
                filename = filename[:max_length]
        
        # Se o nome ficou vazio após sanitização mínima
        if not filename or filename.strip() == '':
            filename = "unnamed_file"
        
        # VERIFICAR NOVAMENTE após sanitização
        is_blocked_final, block_reason_final = FileNameSanitizer.check_blacklist(filename)
        if is_blocked_final:
            raise BlacklistValidationError(block_reason_final)
        
        return filename, True

    @staticmethod
    def generate_safe_key(username: str, filename: str, add_hash: bool = True) -> str:
        """
        Gera uma chave S3 segura para o arquivo
        
        IMPORTANTE: Esta função IRÁ LANÇAR EXCEÇÃO se a extensão estiver bloqueada
        """
        # Sanitizar username (mais restritivo que filename para evitar problemas no S3)
        safe_username = re.sub(r'[^a-zA-Z0-9_-]', '_', username)
        safe_username = safe_username[:50]

        # Sanitizar filename - ISSO VAI VERIFICAR BLACKLIST
        try:
            safe_filename, is_safe = FileNameSanitizer.sanitize_filename(filename)
        except BlacklistValidationError as e:
            logger.error(f"File rejected during key generation: {filename} - {str(e)}")
            raise

        # Para S3, precisamos ser mais restritivos com caracteres especiais
        # S3 tem limitações com alguns caracteres em keys
        # Substituir caracteres problemáticos para S3
        s3_safe_filename = safe_filename
        
        # Caracteres que podem causar problemas no S3
        s3_problematic = ['&', '$', '@', '=', ';', ':', '+', ' ', ',', '?', 
                         '\\', '{', '}', '^', '%', '`', '[', ']', '"', "'",
                         '>', '<', '#', '|', '~']
        
        for char in s3_problematic:
            s3_safe_filename = s3_safe_filename.replace(char, '_')
        
        # Adicionar hash único para evitar colisões
        if add_hash:
            unique_id = secrets.token_hex(4)
            
            # Separar nome e extensão
            parts = s3_safe_filename.rsplit('.', 1)
            if len(parts) == 2:
                base_name, extension = parts
                s3_safe_filename = f"{base_name}_{unique_id}.{extension}"
            else:
                s3_safe_filename = f"{s3_safe_filename}_{unique_id}"

        # Criar estrutura de diretórios segura
        now = datetime.now()
        date_path = f"{now.year:04d}/{now.month:02d}/{now.day:02d}"

        # Montar chave final
        file_key = f"{safe_username}/{date_path}/{s3_safe_filename}"

        # Validação final
        if '..' in file_key or file_key.startswith('/'):
            logger.error(f"Path traversal in final key: {file_key}")
            raise ValueError("Invalid file key generated")

        return file_key

class S3Manager:
    """Gerenciador de operações S3 com BLACKLIST EFETIVA"""

    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str,
                 aws_region: str, s3_bucket: str):
        """Inicializa o gerenciador S3"""
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region
        )
        self.bucket = s3_bucket
        self.sanitizer = FileNameSanitizer()

        if not self._validate_bucket_name(s3_bucket):
            raise ValueError(f"Invalid bucket name: {s3_bucket}")

        logger.info(f"S3Manager initialized for bucket: {s3_bucket} with BLACKLIST protection")

    def _validate_bucket_name(self, bucket_name: str) -> bool:
        """Valida nome do bucket S3"""
        if not bucket_name:
            return False

        if len(bucket_name) < 3 or len(bucket_name) > 63:
            return False

        if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', bucket_name):
            return False

        if '..' in bucket_name or '--' in bucket_name:
            return False

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', bucket_name):
            return False

        return True

    def _validate_file_key(self, file_key: str) -> bool:
        """Valida chave do arquivo para prevenir path traversal"""
        if not file_key:
            return False

        if '..' in file_key:
            logger.error(f"Path traversal detected in key: {file_key}")
            return False

        if file_key.startswith('/') or file_key.startswith('\\'):
            logger.error(f"Absolute path detected: {file_key}")
            return False

        if '\x00' in file_key:
            logger.error(f"Null byte detected in key: {file_key}")
            return False

        if len(file_key) > 1024:
            logger.error(f"Key too long: {len(file_key)} bytes")
            return False

        return True

    def upload_file(self, file_obj, file_key: str, username: str = None) -> bool:
        """
        Faz upload do arquivo para S3 com VALIDAÇÃO DE BLACKLIST
        CORRIGIDO: Metadata com apenas caracteres ASCII
        
        Returns:
            bool: True se upload foi bem-sucedido, False caso contrário
        """
        try:
            # Obter nome original do arquivo
            original_name = getattr(file_obj, 'name', 'uploaded_file')
            
            # Log do nome original para debug
            logger.info(f"Attempting to upload file: {original_name}")
            
            # VERIFICAÇÃO CRÍTICA: Checar blacklist ANTES do upload
            is_blocked, block_reason = self.sanitizer.check_blacklist(original_name)
            if is_blocked:
                logger.error(f"UPLOAD BLOCKED: {original_name} - {block_reason}")
                raise BlacklistValidationError(block_reason)

            # Validar e sanitizar file_key
            if not self._validate_file_key(file_key):
                try:
                    file_key = self.sanitizer.generate_safe_key(
                        username or "anonymous",
                        original_name,
                        add_hash=True
                    )
                    logger.info(f"Generated safe key: {file_key}")
                except BlacklistValidationError as e:
                    logger.error(f"File rejected: {str(e)}")
                    raise

            # Verificar tamanho do arquivo
            file_obj.seek(0, 2)
            file_size = file_obj.tell()
            file_obj.seek(0)

            MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024  # 5GB
            if file_size > MAX_FILE_SIZE:
                logger.error(f"File too large: {file_size} bytes")
                raise FileValidationError(f"Arquivo muito grande. Máximo: 5GB")

            # Ler primeiros bytes para verificação de magic bytes
            file_obj.seek(0)
            first_bytes = file_obj.read(8192)
            file_obj.seek(0)

            # Verificar magic bytes
            is_dangerous, detected_type = self.sanitizer.check_magic_bytes(first_bytes)
            if is_dangerous:
                logger.error(f"UPLOAD BLOCKED by magic bytes: {original_name} - Type: {detected_type}")
                raise BlacklistValidationError(f"Tipo de arquivo perigoso detectado: {detected_type}")

            # Detectar tipo MIME para metadata
            if hasattr(file_obj, 'type'):
                content_type = file_obj.type
            elif hasattr(file_obj, 'name'):
                content_type, _ = mimetypes.guess_type(file_obj.name)
            else:
                content_type = 'application/octet-stream'

            # ============= CORREÇÃO: METADATA ASCII-SAFE =============
            
            # Codificar o nome original em base64 para preservar todos os caracteres
            original_name_b64 = base64.b64encode(original_name.encode('utf-8')).decode('ascii')
            
            # Criar versão ASCII-safe do nome para legibilidade
            original_name_ascii = make_ascii_safe(original_name)
            
            # Metadata adicional (TODOS OS VALORES DEVEM SER ASCII)
            metadata = {
                'uploaded-by': make_ascii_safe(username or 'anonymous'),
                'upload-timestamp': str(datetime.now().isoformat()),
                'original-name-ascii': original_name_ascii[:255],  # Versão legível
                'original-name-b64': original_name_b64,  # Versão completa codificada
                'sanitized': 'true',
                'validated': 'true',
                'detected-type': detected_type
            }
            
            # IMPORTANTE: Não incluir 'original-name' com caracteres não-ASCII

            # Upload para S3
            self.s3_client.upload_fileobj(
                file_obj,
                self.bucket,
                file_key,
                ExtraArgs={
                    'ContentType': content_type or 'application/octet-stream',
                    'Metadata': metadata,
                    'ServerSideEncryption': 'AES256',
                    # Adicionar header para forçar download (não executar no browser)
                    'ContentDisposition': 'attachment'
                }
            )

            logger.info(f"File uploaded securely to S3: {file_key} (validated against blacklist)")
            return True

        except BlacklistValidationError:
            # Re-raise para que o chamador possa tratar
            raise

        except FileValidationError:
            # Re-raise para que o chamador possa tratar
            raise

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"S3 upload error ({error_code}): {e}")
            raise FileValidationError(f"Erro no upload: {error_code}")

        except Exception as e:
            logger.error(f"Unexpected error during S3 upload: {e}")
            raise FileValidationError(f"Erro inesperado: {str(e)}")

    def download_file(self, file_key: str, username: str = None) -> Optional[bytes]:
        """Baixa arquivo do S3 com validação de segurança"""
        try:
            if not self._validate_file_key(file_key):
                logger.error(f"Invalid file key for download: {file_key}")
                return None

            # Verificar acesso básico
            if username and not file_key.startswith(f"{username}/"):
                logger.warning(f"Cross-user access attempt by {username} to {file_key}")

            # Baixar do S3
            response = self.s3_client.get_object(Bucket=self.bucket, Key=file_key)

            # Verificar metadata
            metadata = response.get('Metadata', {})
            if metadata.get('validated') != 'true':
                logger.warning(f"Downloading non-validated file: {file_key}")

            content = response['Body'].read()

            # Verificar magic bytes do conteúdo baixado
            if content:
                is_dangerous, detected_type = self.sanitizer.check_magic_bytes(content[:8192])
                if is_dangerous:
                    logger.error(f"DOWNLOAD BLOCKED: Dangerous content detected in {file_key}")
                    return None

            logger.info(f"File downloaded from S3: {file_key}")
            return content

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == '404' or error_code == 'NoSuchKey':
                logger.error(f"File not found: {file_key}")
            else:
                logger.error(f"S3 download error ({error_code}): {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error during S3 download: {e}")
            return None

    def delete_file(self, file_key: str, username: str = None) -> bool:
        """Deleta arquivo do S3 com validação"""
        try:
            if not self._validate_file_key(file_key):
                logger.error(f"Invalid file key for deletion: {file_key}")
                return False

            if username and not file_key.startswith(f"{username}/"):
                logger.warning(f"User {username} attempting to delete file: {file_key}")
                return False

            self.s3_client.delete_object(Bucket=self.bucket, Key=file_key)
            logger.info(f"File deleted from S3: {file_key}")
            return True

        except ClientError as e:
            logger.error(f"S3 delete error: {e}")
            return False

        except Exception as e:
            logger.error(f"Unexpected error during S3 delete: {e}")
            return False

    def file_exists(self, file_key: str) -> bool:
        """Verifica se um arquivo existe no S3"""
        try:
            if not self._validate_file_key(file_key):
                return False

            self.s3_client.head_object(Bucket=self.bucket, Key=file_key)
            return True

        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return False
            else:
                logger.error(f"Error checking file existence: {e}")
                return False

        except Exception as e:
            logger.error(f"Unexpected error checking file existence: {e}")
            return False

    def list_user_files(self, username: str, prefix: str = None) -> list:
        """Lista arquivos de um usuário específico"""
        try:
            safe_username = re.sub(r'[^a-zA-Z0-9_-]', '_', username)

            if prefix:
                safe_prefix = re.sub(r'[^a-zA-Z0-9_/\-]', '_', prefix)
                if not safe_prefix.startswith(safe_username):
                    safe_prefix = f"{safe_username}/{safe_prefix}"
            else:
                safe_prefix = f"{safe_username}/"

            if '..' in safe_prefix:
                logger.error(f"Path traversal in prefix: {safe_prefix}")
                return []

            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket,
                Prefix=safe_prefix,
                MaxKeys=1000
            )

            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    # Verificar se o arquivo não tem extensão bloqueada
                    file_name = obj['Key'].split('/')[-1]
                    is_blocked, _ = self.sanitizer.check_blacklist(file_name)
                    
                    files.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'],
                        'etag': obj['ETag'],
                        'is_blocked': is_blocked
                    })

            return files

        except Exception as e:
            logger.error(f"Error listing user files: {e}")
            return []

    def generate_presigned_url(self, file_key: str, expiration: int = 3600) -> Optional[str]:
        """Gera URL pré-assinada para download direto"""
        try:
            if not self._validate_file_key(file_key):
                logger.error(f"Invalid file key for presigned URL: {file_key}")
                return None

            # Verificar se o arquivo não tem extensão perigosa
            file_name = file_key.split('/')[-1]
            is_blocked, reason = self.sanitizer.check_blacklist(file_name)
            if is_blocked:
                logger.error(f"Cannot generate URL for blocked file: {file_name}")
                return None

            MAX_EXPIRATION = 7 * 24 * 60 * 60
            if expiration > MAX_EXPIRATION:
                expiration = MAX_EXPIRATION

            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket,
                    'Key': file_key,
                    'ResponseContentDisposition': 'attachment'  # Forçar download
                },
                ExpiresIn=expiration
            )

            logger.info(f"Generated presigned URL for: {file_key}")
            return url

        except Exception as e:
            logger.error(f"Error generating presigned URL: {e}")
            return None

# Função auxiliar para uso em outros módulos
def create_safe_file_key(username: str, filename: str) -> str:
    """
    Cria uma chave de arquivo segura
    LANÇA EXCEÇÃO se arquivo estiver na blacklist
    """
    sanitizer = FileNameSanitizer()
    return sanitizer.generate_safe_key(username, filename, add_hash=True)

# Função para verificar se arquivo está bloqueado
def is_file_blocked(filename: str) -> Tuple[bool, str]:
    """Verifica se arquivo está na blacklist"""
    return FileNameSanitizer.check_blacklist(filename)

# Log de inicialização
logger.info("✅ S3Manager with EFFECTIVE BLACKLIST protection loaded - ASCII-SAFE METADATA")
