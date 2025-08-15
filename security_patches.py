"""
Security Patches Module - VERSÃO ANTI-BYPASS COM PROTEÇÃO MULTICAMADA
Implementa proteções robustas contra bypass de rate limiting
MANTÉM COMPATIBILIDADE TOTAL COM SISTEMA ATUAL
"""
import time
import hashlib
import hmac
import secrets
import logging
import ipaddress
import json
import re
import base64
import struct
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List, Any, Set
from collections import defaultdict, deque
import threading
from functools import wraps
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# ============= CONFIGURAÇÕES AVANÇADAS DE RATE LIMITING =============

class ThreatLevel(Enum):
    """Níveis de ameaça para aplicar diferentes estratégias"""
    LOW = 1
    MEDIUM = 2 
    HIGH = 3
    CRITICAL = 4

@dataclass
class RateLimitRule:
    """Regra de rate limiting com contexto"""
    calls: int
    window: int
    block_duration: int
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    progressive_penalty: bool = True
    require_captcha: bool = False

class AdvancedRateLimitConfig:
    """Configurações avançadas anti-bypass"""
    
    # Limites base (mantém compatibilidade)
    BASE_LIMITS = {
        'login': RateLimitRule(5, 300, 1800, ThreatLevel.HIGH, True, True),
        'api': RateLimitRule(100, 60, 300, ThreatLevel.MEDIUM),
        'upload': RateLimitRule(10, 300, 600, ThreatLevel.MEDIUM),
        'download': RateLimitRule(50, 300, 300, ThreatLevel.LOW),
        'admin': RateLimitRule(20, 60, 600, ThreatLevel.HIGH, True),
        'register': RateLimitRule(3, 3600, 3600, ThreatLevel.HIGH, True, True),
        'password_reset': RateLimitRule(3, 3600, 7200, ThreatLevel.HIGH, True, True),
        'mfa': RateLimitRule(5, 300, 1800, ThreatLevel.HIGH, True),
        'temp_link': RateLimitRule(10, 300, 900, ThreatLevel.MEDIUM),
        'search': RateLimitRule(30, 60, 120, ThreatLevel.LOW),
        'default': RateLimitRule(60, 60, 60, ThreatLevel.LOW)
    }
    
    # Multiplicadores de penalidade progressiva
    PENALTY_MULTIPLIERS = {
        1: 1.0,   # Primeira violação
        2: 2.5,   # Segunda violação
        3: 6.0,   # Terceira violação
        4: 15.0,  # Quarta violação
        5: 50.0,  # Quinta+ violação (muito severo)
    }
    
    # Detecção de padrões suspeitos
    SUSPICIOUS_PATTERNS = {
        'rapid_user_agent_change': 5,  # Mudanças de UA em pouco tempo
        'distributed_attack': 10,      # Mesmo padrão de vários IPs
        'timing_pattern': 3,          # Requests muito regulares
        'header_inconsistency': 3,    # Headers inconsistentes
        'geo_anomaly': 2             # Mudanças geográficas rápidas
    }
    
    # Whitelist e Blacklist dinâmicas
    TRUSTED_NETWORKS: Set[str] = set()  # CIDRs confiáveis
    BLOCKED_NETWORKS: Set[str] = set()  # CIDRs bloqueados
    TRUSTED_USER_AGENTS: Set[str] = set()  # UAs confiáveis
    SUSPICIOUS_USER_AGENTS: Set[str] = {
        'curl', 'wget', 'python-requests', 'postman', 'insomnia',
        'bot', 'crawler', 'spider', 'scraper', 'automation'
    }
    
    # Headers de proxy mais comuns
    PROXY_HEADERS = [
        'x-forwarded-for', 'x-real-ip', 'x-originating-ip', 'cf-connecting-ip',
        'x-forwarded-host', 'x-proxyuser-ip', 'via', 'forwarded',
        'true-client-ip', 'x-client-ip', 'client-ip', 'x-cluster-client-ip',
        'x-azure-clientip', 'x-azure-socketip', 'fastly-client-ip'
    ]

# ============= FINGERPRINTING AVANÇADO =============

class AdvancedFingerprinter:
    """Sistema de fingerprinting robusto contra bypass"""
    
    @staticmethod
    def extract_ip_info(ip: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extrai informações detalhadas do IP"""
        info = {
            'primary_ip': ip,
            'proxy_ips': [],
            'is_proxy': False,
            'is_tor': False,
            'is_vpn': False,
            'is_cloud': False,
            'asn': None,
            'country': None
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            info['is_private'] = ip_obj.is_private
            info['is_loopback'] = ip_obj.is_loopback
            info['is_multicast'] = ip_obj.is_multicast
            
            # Detectar proxy através de headers
            for header in AdvancedRateLimitConfig.PROXY_HEADERS:
                value = headers.get(header, '').lower()
                if value and value not in ['unknown', 'null', '-']:
                    info['proxy_ips'].append(value)
                    info['is_proxy'] = True
            
            # Detectar via header Via
            via_header = headers.get('via', '')
            if via_header:
                info['is_proxy'] = True
                info['proxy_chain'] = via_header
            
            # Detectar Tor (básico)
            if any(tor_indicator in headers.get('user-agent', '').lower() 
                   for tor_indicator in ['tor', 'tails', 'onion']):
                info['is_tor'] = True
            
            # Detectar cloud providers (IPs conhecidos)
            info['is_cloud'] = AdvancedFingerprinter._is_cloud_ip(ip)
            
        except ValueError:
            logger.warning(f"Invalid IP format: {ip}")
            info['is_invalid'] = True
        
        return info
    
    @staticmethod
    def _is_cloud_ip(ip: str) -> bool:
        """Detecta se IP é de provedores cloud conhecidos"""
        # Ranges conhecidos de AWS, GCP, Azure, etc.
        cloud_ranges = [
            '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.0.0.0/8',  # AWS/GCP samples
            '104.0.0.0/8', '23.0.0.0/8', '13.64.0.0/11'  # Azure samples
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in cloud_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
        except:
            pass
        
        return False
    
    @staticmethod
    def analyze_user_agent(user_agent: str) -> Dict[str, Any]:
        """Análise detalhada do User-Agent"""
        if not user_agent:
            return {'is_suspicious': True, 'reason': 'missing_ua'}
        
        ua_lower = user_agent.lower()
        analysis = {
            'is_bot': False,
            'is_suspicious': False,
            'browser_type': 'unknown',
            'os_type': 'unknown',
            'automation_score': 0,
            'reasons': []
        }
        
        # Detectar bots óbvios
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper']
        for indicator in bot_indicators:
            if indicator in ua_lower:
                analysis['is_bot'] = True
                analysis['reasons'].append(f'bot_keyword_{indicator}')
        
        # Detectar ferramentas de automação
        automation_tools = ['curl', 'wget', 'python', 'requests', 'selenium', 
                           'phantomjs', 'puppeteer', 'playwright', 'scrapy']
        for tool in automation_tools:
            if tool in ua_lower:
                analysis['automation_score'] += 3
                analysis['reasons'].append(f'automation_tool_{tool}')
        
        # Detectar padrões suspeitos
        if len(user_agent) < 20:
            analysis['automation_score'] += 2
            analysis['reasons'].append('short_ua')
        
        if len(user_agent) > 500:
            analysis['automation_score'] += 1
            analysis['reasons'].append('long_ua')
        
        # Verificar se contém informações básicas de browser
        browser_indicators = ['mozilla', 'chrome', 'firefox', 'safari', 'edge']
        has_browser = any(browser in ua_lower for browser in browser_indicators)
        if not has_browser and not analysis['is_bot']:
            analysis['automation_score'] += 2
            analysis['reasons'].append('no_browser_info')
        
        # Detectar UAs suspeitos conhecidos
        for suspicious_ua in AdvancedRateLimitConfig.SUSPICIOUS_USER_AGENTS:
            if suspicious_ua in ua_lower:
                analysis['automation_score'] += 4
                analysis['reasons'].append(f'suspicious_ua_{suspicious_ua}')
        
        analysis['is_suspicious'] = analysis['automation_score'] >= 3
        
        return analysis
    
    @staticmethod
    def calculate_request_fingerprint(request_data: Dict[str, Any]) -> str:
        """Calcula fingerprint robusto contra bypass"""
        # Componentes primários (difíceis de mudar)
        primary_factors = []
        
        # IP e informações de rede
        ip_info = request_data.get('ip_info', {})
        primary_ip = ip_info.get('primary_ip', 'unknown')
        primary_factors.append(f"ip:{primary_ip}")
        
        # Se há proxy, incluir chain completa
        proxy_ips = ip_info.get('proxy_ips', [])
        if proxy_ips:
            proxy_chain = '|'.join(sorted(proxy_ips))
            primary_factors.append(f"proxy:{hashlib.md5(proxy_chain.encode()).hexdigest()[:8]}")
        
        # Componentes secundários (fáceis de mudar, mas úteis para detecção)
        secondary_factors = []
        
        # User Agent (hash para reduzir tamanho)
        user_agent = request_data.get('user_agent', '')
        if user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:12]
            secondary_factors.append(f"ua:{ua_hash}")
        
        # Headers de idioma e encoding (mais difíceis de randomizar)
        accept_lang = request_data.get('accept_language', '')
        if accept_lang:
            lang_hash = hashlib.md5(accept_lang.encode()).hexdigest()[:8]
            secondary_factors.append(f"lang:{lang_hash}")
        
        accept_enc = request_data.get('accept_encoding', '')
        if accept_enc:
            enc_hash = hashlib.md5(accept_enc.encode()).hexdigest()[:8]
            secondary_factors.append(f"enc:{enc_hash}")
        
        # TLS fingerprint (se disponível)
        tls_fingerprint = request_data.get('tls_fingerprint', '')
        if tls_fingerprint:
            secondary_factors.append(f"tls:{tls_fingerprint[:12]}")
        
        # Username autenticado (alta confiança)
        username = request_data.get('username', '')
        if username:
            primary_factors.append(f"user:{username}")
        
        # Session ID (se disponível e confiável)
        session_id = request_data.get('session_id', '')
        if session_id and len(session_id) > 10:  # Apenas sessions válidas
            primary_factors.append(f"sess:{session_id[:16]}")
        
        # Combinar fatores
        all_factors = primary_factors + secondary_factors
        identifier = '|'.join(all_factors)
        
        # Hash final com timestamp para rotação
        timestamp_window = int(time.time() // 300)  # 5 min windows
        final_data = f"{identifier}|{timestamp_window}"
        
        return hashlib.sha256(final_data.encode()).hexdigest()

# ============= DETECTOR DE PADRÕES AVANÇADO =============

class PatternDetector:
    """Detecta padrões suspeitos e tentativas de bypass"""
    
    def __init__(self):
        self.user_patterns = defaultdict(lambda: {
            'user_agents': deque(maxlen=10),
            'timing_deltas': deque(maxlen=20),
            'locations': deque(maxlen=5),
            'headers_hash': deque(maxlen=10),
            'first_seen': time.time()
        })
        self.global_patterns = {
            'distributed_attacks': defaultdict(int),
            'timing_clusters': defaultdict(list)
        }
        self.lock = threading.RLock()
    
    def analyze_request_pattern(self, identifier: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisa padrões da requisição para detectar bypass"""
        with self.lock:
            patterns = self.user_patterns[identifier]
            current_time = time.time()
            
            analysis = {
                'suspicious_score': 0,
                'detected_patterns': [],
                'risk_level': ThreatLevel.LOW
            }
            
            # 1. Análise de mudanças de User-Agent
            user_agent = request_data.get('user_agent', '')
            if user_agent:
                patterns['user_agents'].append((current_time, user_agent))
                ua_analysis = self._analyze_user_agent_changes(patterns['user_agents'])
                analysis['suspicious_score'] += ua_analysis['score']
                analysis['detected_patterns'].extend(ua_analysis['patterns'])
            
            # 2. Análise de timing
            if patterns['timing_deltas']:
                last_time = patterns['timing_deltas'][-1][0]
                delta = current_time - last_time
                patterns['timing_deltas'].append((current_time, delta))
                
                timing_analysis = self._analyze_timing_patterns(patterns['timing_deltas'])
                analysis['suspicious_score'] += timing_analysis['score']
                analysis['detected_patterns'].extend(timing_analysis['patterns'])
            else:
                patterns['timing_deltas'].append((current_time, 0))
            
            # 3. Análise de headers
            headers_data = {
                'accept': request_data.get('accept', ''),
                'accept_language': request_data.get('accept_language', ''),
                'accept_encoding': request_data.get('accept_encoding', ''),
                'connection': request_data.get('connection', '')
            }
            headers_hash = hashlib.md5(str(sorted(headers_data.items())).encode()).hexdigest()[:16]
            patterns['headers_hash'].append((current_time, headers_hash))
            
            headers_analysis = self._analyze_header_changes(patterns['headers_hash'])
            analysis['suspicious_score'] += headers_analysis['score']
            analysis['detected_patterns'].extend(headers_analysis['patterns'])
            
            # 4. Análise geográfica (simplificada)
            ip_info = request_data.get('ip_info', {})
            location = ip_info.get('country', 'unknown')
            patterns['locations'].append((current_time, location))
            
            geo_analysis = self._analyze_geographic_changes(patterns['locations'])
            analysis['suspicious_score'] += geo_analysis['score']
            analysis['detected_patterns'].extend(geo_analysis['patterns'])
            
            # 5. Detectar ataques distribuídos
            self._update_distributed_attack_detection(identifier, request_data)
            
            # Determinar nível de risco
            if analysis['suspicious_score'] >= 10:
                analysis['risk_level'] = ThreatLevel.CRITICAL
            elif analysis['suspicious_score'] >= 6:
                analysis['risk_level'] = ThreatLevel.HIGH
            elif analysis['suspicious_score'] >= 3:
                analysis['risk_level'] = ThreatLevel.MEDIUM
            
            return analysis
    
    def _analyze_user_agent_changes(self, user_agents: deque) -> Dict[str, Any]:
        """Analisa mudanças suspeitas de User-Agent"""
        if len(user_agents) < 2:
            return {'score': 0, 'patterns': []}
        
        # Contar mudanças únicas em janela de tempo
        recent_window = time.time() - 300  # 5 minutos
        recent_uas = [ua for timestamp, ua in user_agents if timestamp > recent_window]
        unique_uas = set(recent_uas)
        
        score = 0
        patterns = []
        
        if len(unique_uas) > 3:  # Mais de 3 UAs diferentes em 5 min
            score += 4
            patterns.append('rapid_ua_change')
        
        # Detectar padrão de rotação automática
        if len(unique_uas) == len(recent_uas) and len(recent_uas) > 2:
            score += 3
            patterns.append('automated_ua_rotation')
        
        return {'score': score, 'patterns': patterns}
    
    def _analyze_timing_patterns(self, timing_deltas: deque) -> Dict[str, Any]:
        """Analisa padrões de timing suspeitos"""
        if len(timing_deltas) < 5:
            return {'score': 0, 'patterns': []}
        
        deltas = [delta for _, delta in timing_deltas if delta > 0]
        if not deltas:
            return {'score': 0, 'patterns': []}
        
        score = 0
        patterns = []
        
        # Detectar timing muito regular (bot)
        avg_delta = sum(deltas) / len(deltas)
        variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
        
        if variance < 0.1 and avg_delta > 0.5:  # Muito regular
            score += 3
            patterns.append('regular_timing')
        
        # Detectar requests muito rápidos
        fast_requests = [d for d in deltas if d < 0.1]
        if len(fast_requests) > len(deltas) * 0.5:
            score += 2
            patterns.append('rapid_requests')
        
        return {'score': score, 'patterns': patterns}
    
    def _analyze_header_changes(self, headers_hash: deque) -> Dict[str, Any]:
        """Analisa mudanças suspeitas de headers"""
        if len(headers_hash) < 3:
            return {'score': 0, 'patterns': []}
        
        recent_window = time.time() - 300
        recent_hashes = [h for timestamp, h in headers_hash if timestamp > recent_window]
        unique_hashes = set(recent_hashes)
        
        score = 0
        patterns = []
        
        if len(unique_hashes) > 2:  # Headers mudando frequentemente
            score += 2
            patterns.append('header_variation')
        
        return {'score': score, 'patterns': patterns}
    
    def _analyze_geographic_changes(self, locations: deque) -> Dict[str, Any]:
        """Analisa mudanças geográficas suspeitas"""
        if len(locations) < 2:
            return {'score': 0, 'patterns': []}
        
        recent_window = time.time() - 3600  # 1 hora
        recent_locations = [loc for timestamp, loc in locations if timestamp > recent_window]
        unique_locations = set(recent_locations)
        
        score = 0
        patterns = []
        
        if len(unique_locations) > 2:  # Múltiplas localizações em 1 hora
            score += 3
            patterns.append('geo_hopping')
        
        return {'score': score, 'patterns': patterns}
    
    def _update_distributed_attack_detection(self, identifier: str, request_data: Dict[str, Any]):
        """Detecta ataques distribuídos"""
        action = request_data.get('action', 'unknown')
        user_agent = request_data.get('user_agent', '')
        
        # Criar assinatura do padrão de ataque
        attack_signature = hashlib.md5(f"{action}:{user_agent}".encode()).hexdigest()[:12]
        
        # Incrementar contador
        self.global_patterns['distributed_attacks'][attack_signature] += 1
        
        # Limpar contadores antigos (cleanup simples)
        if len(self.global_patterns['distributed_attacks']) > 1000:
            # Manter apenas os 100 mais ativos
            sorted_attacks = sorted(
                self.global_patterns['distributed_attacks'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            self.global_patterns['distributed_attacks'] = dict(sorted_attacks[:100])

# ============= RATE LIMITER ANTI-BYPASS =============

class AntiBypassRateLimiter:
    """Rate limiter robusto contra tentativas de bypass"""
    
    def __init__(self, storage=None):
        self.storage = storage or self._init_storage()
        self.config = AdvancedRateLimitConfig()
        self.fingerprinter = AdvancedFingerprinter()
        self.pattern_detector = PatternDetector()
        self.adaptive_thresholds = defaultdict(lambda: 1.0)  # Multiplicadores adaptativos
        
        logger.info("AntiBypassRateLimiter initialized with advanced protection")
    
    def _init_storage(self):
        """Inicializa storage com fallback"""
        try:
            # Tentar usar Redis se disponível
            import redis
            redis_client = redis.Redis(
                host='localhost', port=6379, db=0,
                decode_responses=True, socket_connect_timeout=1
            )
            redis_client.ping()
            logger.info("Using Redis for rate limiting storage")
            return RedisRateLimitStorage(redis_client)
        except:
            logger.info("Redis not available, using memory storage")
            return MemoryRateLimitStorage()
    
    def check_rate_limit_robust(
        self,
        action: str,
        request_data: Dict[str, Any],
        custom_limits: Optional[RateLimitRule] = None
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Verificação robusta de rate limit com proteção anti-bypass
        MANTÉM COMPATIBILIDADE com sistema atual
        """
        try:
            # 1. Preparar dados da requisição
            enriched_data = self._enrich_request_data(request_data)
            
            # 2. Verificar blacklist/whitelist primeiro
            trust_check = self._check_trust_lists(enriched_data)
            if trust_check['blocked']:
                return False, trust_check['reason'], trust_check
            if trust_check['trusted']:
                return True, None, {'reason': 'whitelist', 'trusted': True}
            
            # 3. Gerar fingerprint robusto
            primary_identifier = self.fingerprinter.calculate_request_fingerprint(enriched_data)
            
            # 4. Análise de padrões suspeitos
            pattern_analysis = self.pattern_detector.analyze_request_pattern(
                primary_identifier, enriched_data
            )
            
            # 5. Determinar limites adaptativos
            limits = self._get_adaptive_limits(action, pattern_analysis, custom_limits)
            
            # 6. Verificar múltiplos níveis de rate limiting
            multi_level_check = self._check_multi_level_limits(
                action, primary_identifier, enriched_data, limits, pattern_analysis
            )
            
            return multi_level_check
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            # Em caso de erro, aplicar limite conservador
            return False, "Rate limiting system error", {'error': str(e)}
    
    def _enrich_request_data(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enriquece dados da requisição com análises detalhadas"""
        enriched = request_data.copy()
        
        # Análise de IP
        ip = enriched.get('ip', '127.0.0.1')
        headers = enriched.get('headers', {})
        enriched['ip_info'] = self.fingerprinter.extract_ip_info(ip, headers)
        
        # Análise de User-Agent
        user_agent = enriched.get('user_agent', '')
        enriched['ua_analysis'] = self.fingerprinter.analyze_user_agent(user_agent)
        
        # Timestamp para análise temporal
        enriched['timestamp'] = time.time()
        
        return enriched
    
    def _check_trust_lists(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Verifica listas de confiança e bloqueio"""
        ip_info = request_data.get('ip_info', {})
        primary_ip = ip_info.get('primary_ip', '')
        
        # Verificar blacklist de redes
        for blocked_network in self.config.BLOCKED_NETWORKS:
            try:
                if ipaddress.ip_address(primary_ip) in ipaddress.ip_network(blocked_network):
                    return {'blocked': True, 'trusted': False, 'reason': 'IP in blacklist'}
            except:
                continue
        
        # Verificar whitelist de redes confiáveis
        for trusted_network in self.config.TRUSTED_NETWORKS:
            try:
                if ipaddress.ip_address(primary_ip) in ipaddress.ip_network(trusted_network):
                    return {'blocked': False, 'trusted': True, 'reason': 'IP in whitelist'}
            except:
                continue
        
        # Verificar User-Agents suspeitos
        ua_analysis = request_data.get('ua_analysis', {})
        if ua_analysis.get('automation_score', 0) >= 8:
            return {'blocked': True, 'trusted': False, 'reason': 'Automated client detected'}
        
        # Verificar proxies conhecidos maliciosos
        if ip_info.get('is_tor'):
            return {'blocked': True, 'trusted': False, 'reason': 'Tor network blocked'}
        
        return {'blocked': False, 'trusted': False, 'reason': 'normal_traffic'}
    
    def _get_adaptive_limits(
        self,
        action: str,
        pattern_analysis: Dict[str, Any],
        custom_limits: Optional[RateLimitRule]
    ) -> RateLimitRule:
        """Calcula limites adaptativos baseados no risco"""
        base_limits = custom_limits or self.config.BASE_LIMITS.get(
            action, self.config.BASE_LIMITS['default']
        )
        
        # Fator de multiplicação baseado no risco
        risk_level = pattern_analysis.get('risk_level', ThreatLevel.LOW)
        risk_multipliers = {
            ThreatLevel.LOW: 1.0,
            ThreatLevel.MEDIUM: 0.7,
            ThreatLevel.HIGH: 0.4,
            ThreatLevel.CRITICAL: 0.1
        }
        
        multiplier = risk_multipliers[risk_level]
        
        # Aplicar adaptação
        adapted_calls = max(1, int(base_limits.calls * multiplier))
        adapted_window = base_limits.window
        adapted_block = int(base_limits.block_duration * (2.0 - multiplier))
        
        return RateLimitRule(
            calls=adapted_calls,
            window=adapted_window,
            block_duration=adapted_block,
            threat_level=risk_level,
            progressive_penalty=base_limits.progressive_penalty,
            require_captcha=base_limits.require_captcha or risk_level.value >= 3
        )
    
    def _check_multi_level_limits(
        self,
        action: str,
        identifier: str,
        request_data: Dict[str, Any],
        limits: RateLimitRule,
        pattern_analysis: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Verifica rate limiting em múltiplos níveis"""
        
        # Nível 1: Verificar se já está bloqueado
        blocked_until, violation_count = self.storage.get_block_status(identifier, action)
        if blocked_until and time.time() < blocked_until:
            remaining = int(blocked_until - time.time())
            return False, f"Blocked for {remaining}s (violation #{violation_count})", {
                'blocked': True,
                'remaining_seconds': remaining,
                'violation_count': violation_count,
                'level': 'existing_block'
            }
        
        # Nível 2: Verificar limite principal
        attempts = self.storage.get_attempts(identifier, action, limits.window)
        
        if len(attempts) >= limits.calls:
            # Aplicar bloqueio com penalidade progressiva
            block_duration = limits.block_duration
            
            if limits.progressive_penalty:
                current_violations = self.storage.get_violation_count(identifier, action)
                multiplier = self.config.PENALTY_MULTIPLIERS.get(
                    min(current_violations + 1, 5),
                    self.config.PENALTY_MULTIPLIERS[5]
                )
                block_duration = int(block_duration * multiplier)
            
            # Aplicar bloqueio
            self.storage.apply_block(identifier, action, block_duration, current_violations + 1)
            
            # Log detalhado
            logger.warning(
                f"Rate limit exceeded: action={action}, identifier={identifier[:16]}..., "
                f"attempts={len(attempts)}, limit={limits.calls}, risk={pattern_analysis.get('risk_level')}"
            )
            
            return False, f"Rate limit exceeded. Blocked for {block_duration}s", {
                'blocked': True,
                'attempts': len(attempts),
                'limit': limits.calls,
                'block_duration': block_duration,
                'require_captcha': limits.require_captcha,
                'level': 'new_block'
            }
        
        # Nível 3: Verificar limites secundários (IP, User-Agent, etc.)
        secondary_check = self._check_secondary_limits(action, request_data, limits)
        if not secondary_check['allowed']:
            return False, secondary_check['reason'], secondary_check
        
        # Registrar tentativa válida
        self.storage.record_attempt(identifier, action)
        
        # Estatísticas para resposta
        remaining_calls = limits.calls - len(attempts) - 1
        reset_time = min(attempts) + limits.window if attempts else time.time() + limits.window
        
        return True, None, {
            'allowed': True,
            'remaining_calls': remaining_calls,
            'reset_time': reset_time,
            'window': limits.window,
            'risk_level': pattern_analysis.get('risk_level', ThreatLevel.LOW).name.lower(),
            'suspicious_score': pattern_analysis.get('suspicious_score', 0)
        }
    
    def _check_secondary_limits(
        self,
        action: str,
        request_data: Dict[str, Any],
        limits: RateLimitRule
    ) -> Dict[str, Any]:
        """Verifica limites secundários para detectar bypass"""
        
        # Limite por IP (mais restritivo para IPs suspeitos)
        ip_info = request_data.get('ip_info', {})
        primary_ip = ip_info.get('primary_ip', 'unknown')
        
        # Se é proxy/VPN, aplicar limite mais restritivo
        if ip_info.get('is_proxy') or ip_info.get('is_vpn'):
            ip_limit = max(1, limits.calls // 3)  # 1/3 do limite normal
        else:
            ip_limit = limits.calls
        
        ip_attempts = self.storage.get_attempts(f"ip:{primary_ip}", action, limits.window)
        if len(ip_attempts) >= ip_limit:
            return {
                'allowed': False,
                'reason': f'IP rate limit exceeded ({len(ip_attempts)}/{ip_limit})',
                'level': 'ip_limit'
            }
        
        # Limite por User-Agent (para detectar rotação de IPs)
        user_agent = request_data.get('user_agent', '')
        if user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:16]
            ua_limit = limits.calls * 2  # Mais permissivo para UAs legítimos
            
            ua_analysis = request_data.get('ua_analysis', {})
            if ua_analysis.get('is_suspicious', False):
                ua_limit = max(1, limits.calls // 2)  # Mais restritivo para UAs suspeitos
            
            ua_attempts = self.storage.get_attempts(f"ua:{ua_hash}", action, limits.window)
            if len(ua_attempts) >= ua_limit:
                return {
                    'allowed': False,
                    'reason': f'User-Agent rate limit exceeded ({len(ua_attempts)}/{ua_limit})',
                    'level': 'ua_limit'
                }
        
        # Registrar nas chaves secundárias também
        self.storage.record_attempt(f"ip:{primary_ip}", action)
        if user_agent:
            self.storage.record_attempt(f"ua:{ua_hash}", action)
        
        return {'allowed': True}

# ============= STORAGE IMPLEMENTATIONS =============

class MemoryRateLimitStorage:
    """Storage em memória thread-safe"""
    
    def __init__(self):
        self.attempts = defaultdict(lambda: deque(maxlen=1000))
        self.blocks = {}  # {key: (until_timestamp, violation_count)}
        self.violations = defaultdict(int)
        self.lock = threading.RLock()
    
    def record_attempt(self, identifier: str, action: str):
        with self.lock:
            key = f"{action}:{identifier}"
            self.attempts[key].append(time.time())
    
    def get_attempts(self, identifier: str, action: str, window: int) -> List[float]:
        with self.lock:
            key = f"{action}:{identifier}"
            cutoff = time.time() - window
            
            # Filtrar tentativas antigas
            self.attempts[key] = deque(
                (t for t in self.attempts[key] if t > cutoff),
                maxlen=1000
            )
            
            return list(self.attempts[key])
    
    def get_block_status(self, identifier: str, action: str) -> Tuple[Optional[float], int]:
        with self.lock:
            key = f"{action}:{identifier}"
            if key in self.blocks:
                until, count = self.blocks[key]
                if time.time() < until:
                    return until, count
                else:
                    # Limpar bloqueio expirado
                    del self.blocks[key]
            return None, 0
    
    def apply_block(self, identifier: str, action: str, duration: int, violation_count: int):
        with self.lock:
            key = f"{action}:{identifier}"
            until = time.time() + duration
            self.blocks[key] = (until, violation_count)
            self.violations[key] = violation_count
    
    def get_violation_count(self, identifier: str, action: str) -> int:
        with self.lock:
            key = f"{action}:{identifier}"
            return self.violations.get(key, 0)

class RedisRateLimitStorage:
    """Storage em Redis para ambiente distribuído"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def record_attempt(self, identifier: str, action: str):
        key = f"rate_limit:attempts:{action}:{identifier}"
        pipe = self.redis.pipeline()
        pipe.zadd(key, {str(time.time()): time.time()})
        pipe.expire(key, 3600)  # 1 hora
        pipe.execute()
    
    def get_attempts(self, identifier: str, action: str, window: int) -> List[float]:
        key = f"rate_limit:attempts:{action}:{identifier}"
        cutoff = time.time() - window
        
        # Remover tentativas antigas
        self.redis.zremrangebyscore(key, 0, cutoff)
        
        # Obter tentativas válidas
        attempts = self.redis.zrangebyscore(key, cutoff, time.time())
        return [float(a) for a in attempts]
    
    def get_block_status(self, identifier: str, action: str) -> Tuple[Optional[float], int]:
        block_key = f"rate_limit:block:{action}:{identifier}"
        violation_key = f"rate_limit:violations:{action}:{identifier}"
        
        until = self.redis.get(block_key)
        violations = self.redis.get(violation_key)
        
        if until:
            until_float = float(until)
            if time.time() < until_float:
                return until_float, int(violations or 1)
        
        return None, 0
    
    def apply_block(self, identifier: str, action: str, duration: int, violation_count: int):
        block_key = f"rate_limit:block:{action}:{identifier}"
        violation_key = f"rate_limit:violations:{action}:{identifier}"
        
        until = time.time() + duration
        
        pipe = self.redis.pipeline()
        pipe.setex(block_key, duration, until)
        pipe.setex(violation_key, 86400, violation_count)  # 24h
        pipe.execute()
    
    def get_violation_count(self, identifier: str, action: str) -> int:
        violation_key = f"rate_limit:violations:{action}:{identifier}"
        violations = self.redis.get(violation_key)
        return int(violations or 0)

# ============= INTEGRAÇÃO COM SISTEMA ATUAL =============

class SecurityPatchesRateLimiterV2:
    """Sistema de rate limiting compatível com versão atual"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.rate_limiter = AntiBypassRateLimiter()
            self.initialized = True
            logger.info("SecurityPatchesRateLimiterV2 initialized with anti-bypass protection")
    
    def check_request(
        self,
        action: str,
        ip: str,
        username: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Tuple[bool, Optional[str], Dict]:
        """
        MANTÉM COMPATIBILIDADE TOTAL com sistema atual
        Método principal de verificação com proteções avançadas
        """
        # Preparar dados da requisição
        request_data = {
            'ip': ip,
            'username': username,
            'action': action,
            'user_agent': headers.get('User-Agent', '') if headers else '',
            'headers': headers or {},
            'session_id': kwargs.get('session_id', ''),
            'device_id': kwargs.get('device_id', ''),
        }
        
        # Adicionar headers relevantes se disponíveis
        if headers:
            request_data.update({
                'accept': headers.get('Accept', ''),
                'accept_language': headers.get('Accept-Language', ''),
                'accept_encoding': headers.get('Accept-Encoding', ''),
                'connection': headers.get('Connection', ''),
                'dnt': headers.get('DNT', ''),
            })
        
        # Usar novo sistema de rate limiting anti-bypass
        return self.rate_limiter.check_rate_limit_robust(action, request_data)
    
    # Métodos de compatibilidade com sistema anterior
    def check_rate_limit(self, action: str, request_data: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict]:
        """Método de compatibilidade"""
        return self.rate_limiter.check_rate_limit_robust(action, request_data)

# ============= FUNÇÕES DE INTEGRAÇÃO =============

def get_security_system() -> Dict:
    """Retorna sistema de segurança atualizado com anti-bypass"""
    
    rate_limiter = SecurityPatchesRateLimiterV2()
    
    def apply_rate_limit(action: str = 'default'):
        """Decorator mantendo compatibilidade total"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                import streamlit as st
                
                # Extrair informações da requisição
                ip = kwargs.get('ip', '127.0.0.1')
                username = st.session_state.get('username')
                
                # Simular headers básicos se não disponível
                headers = kwargs.get('headers', {
                    'User-Agent': 'Streamlit-App',
                    'Accept': 'text/html',
                    'Accept-Language': 'pt-BR,pt;q=0.9'
                })
                
                # Verificar rate limit com novo sistema
                allowed, error_msg, details = rate_limiter.check_request(
                    action=action,
                    ip=ip,
                    username=username,
                    headers=headers,
                    session_id=st.session_state.get('session_id', ''),
                )
                
                if not allowed:
                    # Mostrar mensagem amigável baseada no nível de risco
                    risk_level = details.get('risk_level', 'medium')
                    
                    if risk_level == 'critical':
                        st.error(f"🚨 {error_msg}")
                        st.warning("Sistema detectou atividade automatizada. Contate o suporte se necessário.")
                    elif details.get('require_captcha'):
                        st.error(f"🤖 {error_msg}")
                        st.info("Verificação adicional necessária. Aguarde e tente novamente.")
                    else:
                        st.error(f"⚠️ {error_msg}")
                    
                    if details.get('remaining_seconds'):
                        st.info(f"⏳ Tente novamente em {details['remaining_seconds']} segundos")
                    
                    return None
                
                # Adicionar informações de rate limit para monitoramento
                kwargs['_rate_limit_info'] = details
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def get_client_ip() -> str:
        """Obtém IP do cliente - mantém compatibilidade"""
        try:
            # Em produção, usar headers apropriados do load balancer
            import streamlit as st
            return st.session_state.get('client_ip', '127.0.0.1')
        except:
            return "127.0.0.1"
    
    return {
        'rate_limiter': rate_limiter,
        'apply_rate_limit': apply_rate_limit,
        'get_client_ip': get_client_ip,
        'status': 'active_anti_bypass',
        'version': '3.0.0',
        'features': [
            'multi_level_fingerprinting',
            'pattern_detection',
            'adaptive_limits',
            'anti_proxy_bypass',
            'distributed_attack_detection',
            'progressive_penalties'
        ]
    }

# ============= UTILITÁRIOS PARA ADMINISTRADORES =============

def reset_rate_limits(identifier: str = None, action: str = None):
    """Utilitário para admins resetarem rate limits"""
    rate_limiter = SecurityPatchesRateLimiterV2()
    
    if identifier and action:
        # Reset específico
        rate_limiter.rate_limiter.storage.clear_identifier(identifier, action)
        logger.info(f"Rate limit reset for {identifier}:{action}")
    else:
        logger.warning("Reset requires both identifier and action")

def get_rate_limit_stats() -> Dict[str, Any]:
    """Obtém estatísticas de rate limiting para monitoramento"""
    rate_limiter = SecurityPatchesRateLimiterV2()
    
    # Retornar estatísticas básicas (implementação depende do storage)
    return {
        'active_blocks': 0,  # Seria implementado no storage
        'total_violations': 0,
        'system_status': 'active',
        'protection_level': 'maximum'
    }

# Log de inicialização
logger.info("🛡️ Security Patches V3.0 with Advanced Anti-Bypass Protection loaded successfully")
