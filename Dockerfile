FROM python:3.9-slim

# Metadados da imagem
LABEL maintainer="Pluxee Group"
LABEL description="Gerenciador de Arquivos - Versão Completa com Sistema de Usuários e Relatórios Avançados"
LABEL version="3.1"

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    git \
    ca-certificates \
    gnupg \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Criar usuário não-root com UID específico para segurança
RUN groupadd -r appgroup --gid=1000 && \
    useradd -r -g appgroup --uid=1000 --home-dir=/app --shell=/bin/bash app

# Criar diretório da aplicação com permissões corretas
WORKDIR /app
RUN mkdir -p /app/assets /app/logs /app/.streamlit && \
    chown -R app:appgroup /app && \
    chmod -R 750 /app

# Copiar requirements primeiro (para melhor cache do Docker)
COPY requirements.txt .

# Instalar dependências Python com upgrade do pip
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Copiar configuração do Streamlit
COPY .streamlit/config.toml /app/.streamlit/config.toml

# Copiar logo da empresa (opcional)
# IMPORTANTE: Coloque seu logo.png na mesma pasta do Dockerfile
COPY logo.png /app/assets/logo.png

# Copiar todos os módulos da aplicação
COPY --chown=app:appgroup main.py .
COPY --chown=app:appgroup config.py .
COPY --chown=app:appgroup database.py .
COPY --chown=app:appgroup s3_manager.py .
COPY --chown=app:appgroup session_manager.py .
COPY --chown=app:appgroup mfa.py .
COPY --chown=app:appgroup ui_components.py .
COPY --chown=app:appgroup pages.py .
COPY --chown=app:appgroup security_patches.py .
COPY --chown=app:appgroup upload_monitor.py .
COPY --chown=app:appgroup fix_reports.py .
COPY --chown=app:appgroup fix_decimal_error.py .
COPY --chown=app:appgroup integrate_delete_users.py .


# Copiar módulos do sistema de usuários
COPY --chown=app:appgroup simplified_security.py .
COPY --chown=app:appgroup enhanced_upload_monitor.py .
COPY --chown=app:appgroup user_management.py .
COPY --chown=app:appgroup admin_pages.py .
COPY --chown=app:appgroup concurrent_upload_ui.py .

# 🆕 NOVOS ARQUIVOS CRIADOS HOJE - SISTEMA DE RELATÓRIOS AVANÇADOS
COPY --chown=app:appgroup enhanced_admin_reports.py .
COPY --chown=app:appgroup admin_reports_data.py .
COPY --chown=app:appgroup reports_config.py .
COPY --chown=app:appgroup setup_reports.py .

#COPY --chown=app:appgroup test_concurrent_uploads.py .

# Configurar variáveis de ambiente padrão
ENV COMPANY_NAME="Pluxee Group"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Configurações de segurança
ENV SECURITY_ENABLED="true"
ENV DEFAULT_RATE_LIMIT="100"
ENV MAX_LOGIN_ATTEMPTS="3"
ENV BLOCK_DURATION_MINUTES="15"

# 🆕 CONFIGURAÇÕES PARA RELATÓRIOS
ENV REPORTS_ENV="production"
ENV REPORTS_CACHE_DURATION="300"

# Mudar para usuário não-root
USER app

# Expor porta
EXPOSE 8501

# Health check melhorado
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Verificar estrutura de arquivos (opcional, para debug)
RUN ls -la /app/

# Comando para iniciar a aplicação com configurações de segurança
ENTRYPOINT ["streamlit", "run", "main.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--server.fileWatcherType=none", \
    "--server.maxUploadSize=2048", \
    "--server.enableCORS=false", \
    "--server.enableXsrfProtection=true"]
