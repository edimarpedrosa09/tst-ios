"""
Módulo para gerenciamento de MFA (Multi-Factor Authentication)
"""
import io
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Verificação de dependências MFA
try:
    import pyotp
    import qrcode
    from PIL import Image
    MFA_AVAILABLE = True
    logger.info("MFA libraries loaded successfully")
except ImportError as e:
    MFA_AVAILABLE = False
    logger.error(f"MFA libraries not available: {e}")


class MFAManager:
    """Gerenciador de operações MFA"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        
        if not MFA_AVAILABLE:
            logger.warning("MFA functionality not available - missing dependencies")
    
    @staticmethod
    def is_available() -> bool:
        """Verifica se MFA está disponível"""
        return MFA_AVAILABLE
    
    def get_user_mfa_info(self, username: str) -> Tuple[Optional[str], bool]:
        """Retorna (mfa_secret, mfa_enabled) do usuário"""
        if not MFA_AVAILABLE:
            return None, False
            
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT mfa_secret, mfa_enabled FROM users
            WHERE username = %s
        """, (username,))

        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result:
            return result[0], result[1]
        return None, False

    def setup_mfa_for_user(self, username: str) -> Optional[str]:
        """Configura MFA para usuário e retorna o secret"""
        if not MFA_AVAILABLE:
            logger.error("MFA not available - cannot setup MFA")
            return None
            
        secret = pyotp.random_base32()

        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET mfa_secret = %s, mfa_enabled = FALSE
            WHERE username = %s
        """, (secret, username))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"MFA secret generated for user: {username}")
        return secret

    def verify_mfa_token(self, username: str, token: str) -> bool:
        """Verifica token MFA"""
        if not MFA_AVAILABLE:
            logger.error("MFA not available - cannot verify token")
            return False
            
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT mfa_secret FROM users
                WHERE username = %s AND mfa_enabled = TRUE
            """, (username,))

            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if result and result[0]:
                totp = pyotp.TOTP(result[0])
                is_valid = totp.verify(token, valid_window=1)
                if is_valid:
                    logger.info(f"MFA token verified successfully for user: {username}")
                else:
                    logger.warning(f"Invalid MFA token for user: {username}")
                return is_valid
            else:
                logger.error(f"MFA secret not found for user: {username}")
                return False
        except Exception as e:
            logger.error(f"Error verifying MFA token: {e}")
            return False

    def enable_mfa_for_user(self, username: str, token: str) -> bool:
        """Ativa MFA após verificar o primeiro token"""
        if not MFA_AVAILABLE:
            logger.error("MFA not available - cannot enable MFA")
            return False
            
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT mfa_secret FROM users
            WHERE username = %s AND mfa_secret IS NOT NULL
        """, (username,))

        result = cursor.fetchone()

        if result and result[0]:
            totp = pyotp.TOTP(result[0])
            if totp.verify(token, valid_window=1):
                cursor.execute("""
                    UPDATE users
                    SET mfa_enabled = TRUE
                    WHERE username = %s
                """, (username,))

                conn.commit()
                cursor.close()
                conn.close()
                
                logger.info(f"MFA enabled for user: {username}")
                return True

        cursor.close()
        conn.close()
        logger.warning(f"Failed to enable MFA for user: {username}")
        return False

    def disable_mfa_for_user(self, username: str):
        """Desativa MFA para usuário"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET mfa_secret = NULL, mfa_enabled = FALSE
            WHERE username = %s
        """, (username,))

        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"MFA disabled for user: {username}")

    def generate_qr_code(self, username: str, secret: str, issuer: str = "File Manager") -> Optional[io.BytesIO]:
        """Gera QR Code para configuração do Google Authenticator"""
        if not MFA_AVAILABLE:
            logger.error("MFA not available - cannot generate QR code")
            return None
            
        try:
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username,
                issuer_name=issuer
            )

            qr = qrcode.QRCode(
                version=1,
                box_size=10,
                border=5,
                error_correction=qrcode.constants.ERROR_CORRECT_L
            )
            qr.add_data(totp_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            if img.mode != 'RGB':
                img = img.convert('RGB')

            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_bytes.seek(0)

            logger.info(f"QR code generated for user: {username}")
            return img_bytes

        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            return None
