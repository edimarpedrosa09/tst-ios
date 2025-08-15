"""
Configuração dos Relatórios Administrativos
Arquivo: reports_config.py
Configure cores, métricas e alertas para os relatórios
"""

# Configurações de cores para gráficos
CHART_COLORS = {
    'primary': '#1f77b4',
    'secondary': '#ff7f0e', 
    'success': '#28a745',
    'warning': '#ffc107',
    'danger': '#dc3545',
    'info': '#17a2b8',
    'light': '#f8f9fa',
    'dark': '#343a40'
}

# Cores por status
STATUS_COLORS = {
    'active': '#28a745',
    'inactive': '#dc3545',
    'pending': '#ffc107',
    'suspended': '#fd7e14',
    'locked': '#6f42c1'
}

# Cores por role
ROLE_COLORS = {
    'super_admin': '#dc3545',
    'admin': '#fd7e14', 
    'manager': '#ffc107',
    'user': '#28a745',
    'guest': '#6c757d'
}

# Cores por tipo de arquivo
FILE_TYPE_COLORS = {
    'Imagem': '#e74c3c',
    'Vídeo': '#3498db',
    'Áudio': '#9b59b6',
    'Documento': '#f39c12',
    'PDF': '#e67e22',
    'Office': '#2ecc71',
    'Arquivo': '#34495e',
    'Outros': '#95a5a6'
}

# Configurações de alertas
ALERT_THRESHOLDS = {
    'mfa_adoption_low': 50,        # % mínima de adoção MFA
    'login_success_rate_low': 90,   # % mínima de sucesso em login
    'storage_growth_high': 10,      # GB de crescimento para alertar
    'failed_logins_high': 100,      # Número de falhas para alertar
    'inactive_users_high': 30,      # % de usuários inativos para alertar
    'upload_failure_rate_high': 5   # % de falhas de upload para alertar
}

# Configurações de métricas
METRICS_CONFIG = {
    'refresh_interval': 300,        # Segundos entre atualizações automáticas
    'max_chart_points': 100,        # Máximo de pontos em gráficos de linha
    'default_period_days': 30,      # Período padrão para análises
    'top_users_limit': 10,          # Número de usuários no ranking
    'recent_activity_hours': 24     # Horas para considerar atividade recente
}

# Configurações de performance
PERFORMANCE_CONFIG = {
    'query_timeout': 30,            # Timeout para queries em segundos
    'cache_duration': 300,          # Duração do cache em segundos
    'max_records_display': 1000,    # Máximo de registros para mostrar
    'pagination_size': 50           # Registros por página
}

# Configurações de exportação
EXPORT_CONFIG = {
    'formats': ['CSV', 'Excel', 'PDF'],
    'max_export_records': 10000,
    'include_charts_in_pdf': True,
    'chart_export_format': 'PNG'
}

# Templates de mensagens
ALERT_MESSAGES = {
    'mfa_low': "⚠️ Adoção de MFA abaixo do recomendado: {rate:.1f}% (meta: {threshold}%)",
    'login_failures': "🚨 Taxa de falhas de login alta: {rate:.1f}% ({count} falhas)",
    'storage_growth': "📈 Crescimento significativo de armazenamento: {growth:.1f}GB",
    'inactive_users': "👥 Muitos usuários inativos: {rate:.1f}% ({count} usuários)",
    'upload_failures': "📤 Taxa de falhas de upload preocupante: {rate:.1f}%"
}

# Configurações de dashboard
DASHBOARD_CONFIG = {
    'auto_refresh': True,
    'refresh_interval': 30,         # Segundos
    'show_trends': True,
    'show_alerts': True,
    'compact_mode': False,
    'dark_mode': False
}

# Configurações de gráficos
CHART_CONFIG = {
    'height': 400,
    'show_legend': True,
    'responsive': True,
    'animation_duration': 750,
    'font_family': 'Arial, sans-serif',
    'font_size': 12
}

# Configurações de tabelas
TABLE_CONFIG = {
    'page_size': 25,
    'sortable': True,
    'searchable': True,
    'show_index': False,
    'alternating_rows': True
}

# Mapeamento de ícones
ICONS = {
    'users': '👥',
    'files': '📁', 
    'security': '🔐',
    'performance': '📈',
    'storage': '💾',
    'uploads': '📤',
    'downloads': '📥',
    'login': '🔑',
    'admin': '🛡️',
    'alert': '⚠️',
    'success': '✅',
    'error': '❌',
    'info': 'ℹ️',
    'chart': '📊',
    'report': '📋',
    'dashboard': '🎛️'
}

# Configurações específicas por tipo de relatório
REPORT_CONFIGS = {
    'users': {
        'show_growth_chart': True,
        'show_activity_heatmap': True,
        'show_department_breakdown': True,
        'include_login_stats': True
    },
    'files': {
        'show_type_distribution': True,
        'show_size_histogram': True,
        'show_timeline': True,
        'include_download_stats': True
    },
    'security': {
        'show_login_attempts': True,
        'show_mfa_stats': True,
        'show_ip_analysis': True,
        'include_threat_detection': True
    },
    'performance': {
        'show_response_times': True,
        'show_upload_performance': True,
        'show_system_load': True,
        'include_optimization_tips': True
    }
}

# Funções auxiliares para configuração
def get_chart_color_palette(chart_type='default'):
    """Retorna paleta de cores para gráficos"""
    palettes = {
        'default': list(CHART_COLORS.values()),
        'status': list(STATUS_COLORS.values()),
        'roles': list(ROLE_COLORS.values()),
        'files': list(FILE_TYPE_COLORS.values())
    }
    return palettes.get(chart_type, palettes['default'])

def get_alert_config(alert_type):
    """Retorna configuração específica de alerta"""
    return {
        'threshold': ALERT_THRESHOLDS.get(f"{alert_type}_threshold", 0),
        'message_template': ALERT_MESSAGES.get(alert_type, "Alerta: {message}"),
        'severity': 'warning'  # Pode ser 'info', 'warning', 'error'
    }

def get_chart_config(chart_type='default'):
    """Retorna configuração específica para tipos de gráfico"""
    base_config = CHART_CONFIG.copy()
    
    chart_specific = {
        'pie': {'show_legend': True, 'height': 350},
        'bar': {'show_legend': False, 'height': 400},
        'line': {'show_legend': True, 'height': 300},
        'heatmap': {'show_legend': False, 'height': 500},
        'scatter': {'show_legend': False, 'height': 400}
    }
    
    if chart_type in chart_specific:
        base_config.update(chart_specific[chart_type])
    
    return base_config

def format_metric_value(value, metric_type):
    """Formata valores de métricas para exibição"""
    formatters = {
        'count': lambda x: f"{int(x):,}",
        'percentage': lambda x: f"{float(x):.1f}%",
        'bytes': lambda x: format_bytes(int(x)),
        'seconds': lambda x: format_time(float(x)),
        'rate': lambda x: f"{float(x):.2f}"
    }
    
    formatter = formatters.get(metric_type, str)
    return formatter(value)

def format_bytes(bytes_value):
    """Formata bytes para leitura humana"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def format_time(seconds):
    """Formata tempo para leitura humana"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

# Configurações para diferentes ambientes
ENVIRONMENT_CONFIGS = {
    'development': {
        'debug_mode': True,
        'mock_data': True,
        'show_query_times': True,
        'cache_disabled': True
    },
    'staging': {
        'debug_mode': False,
        'mock_data': False,
        'show_query_times': True,
        'cache_disabled': False
    },
    'production': {
        'debug_mode': False,
        'mock_data': False,
        'show_query_times': False,
        'cache_disabled': False
    }
}

# Configuração ativa (pode ser alterada via variável de ambiente)
import os
ACTIVE_ENVIRONMENT = os.getenv('REPORTS_ENV', 'production')
CURRENT_CONFIG = ENVIRONMENT_CONFIGS.get(ACTIVE_ENVIRONMENT, ENVIRONMENT_CONFIGS['production'])

# Exportar configurações principais
__all__ = [
    'CHART_COLORS', 'STATUS_COLORS', 'ROLE_COLORS', 'FILE_TYPE_COLORS',
    'ALERT_THRESHOLDS', 'METRICS_CONFIG', 'PERFORMANCE_CONFIG',
    'DASHBOARD_CONFIG', 'CHART_CONFIG', 'TABLE_CONFIG', 'ICONS',
    'get_chart_color_palette', 'get_alert_config', 'get_chart_config',
    'format_metric_value', 'format_bytes', 'format_time'
]
