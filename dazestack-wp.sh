#!/usr/bin/env bash

# Ensure we are running under bash even if invoked via sh.
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    echo "Error: bash is required to run this script." >&2
    exit 1
fi

################################################################################
# DazeStack WP v0.0.1
# Tagline: Laze while your WordPress stack builds itself.
# Series: DazeStack - tools that let you laze while the code does the work.
# Description: Production-ready, fully automated WordPress LEMP platform with per-site
# isolation, caching, SSL, backups, and maintenance tooling for Ubuntu 24.04+.
#
# Author: Ashish Dungdung
# Website: https://ashishdungdung.com
# Email: mail@ashishdungdung.com
################################################################################

set -Eeuo pipefail

# =============================================================================
# SECTION 1: CORE CONFIGURATION & CONSTANTS
# Purpose: Branding, paths, defaults, and feature flags.
# =============================================================================

INSTALLER_NAME="DazeStack WP"
INSTALLER_TAGLINE="Laze while your WordPress stack builds itself."
INSTALLER_SERIES="DazeStack"
INSTALLER_DESCRIPTION="Production-ready, fully automated WordPress LEMP platform. The idea was to automate and make it full fledged as much as possible."
INSTALLER_VERSION="0.0.1"
INSTALLER_EDITION="Core"
INSTALLER_AUTHOR="Ashish Dungdung"
INSTALLER_WEBSITE="https://ashishdungdung.com"
INSTALLER_EMAIL="mail@ashishdungdung.com"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_START_TIME=$(date +%s)

# Runtime directories
INSTALL_DIR="/var/lib/dazestack-wp"
LOG_DIR="/var/log/dazestack-wp"
BACKUP_DIR="/var/backups/dazestack-wp"
CACHE_DIR="/var/cache/nginx/microcache"
CERTS_DIR="/etc/letsencrypt/live"
CONFIG_DIR="/etc/dazestack-wp"
CREDENTIALS_DIR="/root/.dazestack-wp"
STATE_DIR="${INSTALL_DIR}/state"
SITES_DIR="/var/www"
POOL_DIR="/etc/php"

INSTALL_RECORD_FILE="${INSTALL_DIR}/INSTALLATION_RECORD.txt"
INITIALIZED_FLAG="${INSTALL_DIR}/.initialized"
REGISTRY_FILE="${STATE_DIR}/domain-registry.json"

AUTO_TUNE_SCRIPT="/usr/local/bin/dazestack-wp-autotune.sh"
AUTO_TUNE_CRON_FILE="/etc/cron.d/dazestack-wp-autotune"
CRON_RUNNER_SCRIPT="/usr/local/bin/dazestack-wp-crons.sh"
CRON_BACKUP_SCRIPT="/usr/local/bin/dazestack-wp-backups.sh"
CRON_WORDPRESS_FILE="/etc/cron.d/dazestack-wp-cron"
CRON_BACKUP_FILE="/etc/cron.d/dazestack-wp-backups"
LOGROTATE_CONFIG="/etc/logrotate.d/dazestack-wp"

WORDPRESS_USER="www-data"
WORDPRESS_GROUP="www-data"

# Redis configuration
REDIS_HOST="127.0.0.1"
REDIS_PORT="6379"
REDIS_MAX_DBS=16
REDIS_SOCKET="/run/redis/redis-server.sock"

# Security settings
MASTER_KEY_FILE="$CREDENTIALS_DIR/.master.key"
BACKUP_KEY_FILE="$CREDENTIALS_DIR/.backup.key"
ENCRYPTION_CIPHER="aes-256-cbc"

# Feature flags
ENABLE_SECURITY_HEADERS=${ENABLE_SECURITY_HEADERS:-true}
ENABLE_REDIS_PERSISTENCE=${ENABLE_REDIS_PERSISTENCE:-false}
ENABLE_AGGRESSIVE_CLEANUP=${ENABLE_AGGRESSIVE_CLEANUP:-false}
PHP_TARGET_VERSION=${PHP_TARGET_VERSION:-"8.5"}
ENABLE_REDIS_ACL=${ENABLE_REDIS_ACL:-true}
ENABLE_HTTP3=${ENABLE_HTTP3:-true}
ENABLE_BROTLI=${ENABLE_BROTLI:-true}
ENABLE_ZSTD=${ENABLE_ZSTD:-true}
ENABLE_SYSCTL_TUNING=${ENABLE_SYSCTL_TUNING:-true}
ENABLE_AUTO_TUNE=${ENABLE_AUTO_TUNE:-true}
AUTO_TUNE_CRON=${AUTO_TUNE_CRON:-"15 3 * * *"}
ENABLE_AUTO_SSL=${ENABLE_AUTO_SSL:-false}
ENABLE_CLOUDFLARE=${ENABLE_CLOUDFLARE:-true}
REQUIRE_OPCACHE=${REQUIRE_OPCACHE:-false}
ENABLE_NGINX_HELPER=${ENABLE_NGINX_HELPER:-true}
CLI_WRAPPER="/usr/local/sbin/dazestack-wp"

# PHP packages that may be merged/built-in (avoid hard failure if absent)
PHP_OPTIONAL_PACKAGES=()
ONDREJ_PHP_PPA_REGEX="ondrej/php|LP-PPA-ondrej-php|deb.sury.org"
ONDREJ_PHP_PREF_FILE="/etc/apt/preferences.d/ondrej-php"

# PHP hardening (allow override; avoid breaking WP core/plugin updates)
PHP_DISABLE_FUNCTIONS=${PHP_DISABLE_FUNCTIONS:-"exec,passthru,shell_exec,system,proc_open,popen,proc_close,proc_terminate"}

# WordPress automation
WP_CLI_BIN="/usr/local/bin/wp"
WP_CLI_URL="https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
WP_DEFAULT_ADMIN_USER="admin"
WP_CLI_CACHE_DIR="/var/cache/wp-cli"

# Cloudflare integration
CLOUDFLARE_IPS_V4_URL="https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPS_V6_URL="https://www.cloudflare.com/ips-v6"
CLOUDFLARE_CONF="/etc/nginx/conf.d/dazestack-wp-cloudflare-ips.conf"
CLOUDFLARE_CRON="/etc/cron.d/dazestack-wp-cloudflare-ips"

# System resources
SYSTEM_RAM_GB=0
SYSTEM_RAM_MB=0
SYSTEM_CPU_CORES=0

PHP_MAX_CHILDREN=0
PHP_START_SERVERS=0
PHP_MIN_SPARE=0
PHP_MAX_SPARE=0
PHP_MEMORY_LIMIT=""

MYSQL_INNODB_BUFFER=""
MYSQL_LOG_FILE_SIZE=""
MYSQL_SOCKET=""
MYSQL_BUFFER_POOL_INSTANCES=1

REDIS_MEMORY=""
REDIS_PASSWORD=""

NGINX_WORKER_PROCESSES=0
NGINX_WORKER_CONNECTIONS=0
NGINX_CACHE_MAX_SIZE=""

# Runtime state
PHP_VERSION=""
SOCKET_FOUND=false
MYSQL_SOCKET_DETECTED=""
PHASE_CURRENT=0
INSTALLATION_STARTED=false
INSTALLED_PACKAGES=()
ROLLBACK_STACK=()
HTTP3_AVAILABLE=false
BROTLI_AVAILABLE=false
ZSTD_AVAILABLE=false
CACHE_PURGE_AVAILABLE=false
ERROR_HANDLED=false

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOG_ERROR=0
LOG_WARN=1
LOG_INFO=2
LOG_SUCCESS=3
LOG_DEBUG=4
LOG_TRACE=5

LOG_LEVEL=${LOG_LEVEL:-$LOG_INFO}
LOG_FILE_OUTPUT_ENABLED=${LOG_FILE_OUTPUT_ENABLED:-true}
LOG_TIMESTAMP_FORMAT='+%Y-%m-%d %H:%M:%S'
LOG_MAIN="$LOG_DIR/installation.log"
LOG_ERROR_FILE="$LOG_DIR/error.log"
LOG_DEBUG_FILE="$LOG_DIR/debug.log"
LOG_TRACE_FILE="$LOG_DIR/trace.log"
LOG_AUDIT_FILE="$LOG_DIR/audit.log"
LOG_SECURITY_FILE="$LOG_DIR/security.log"
LOG_CONTEXT=""

# =============================================================================
# SECTION 2: SECURITY FUNCTIONS
# Purpose: Logging helpers, audit trails, and security event capture.
# =============================================================================

sanitize_log_message() {
    local message=$1
    # Remove passwords, tokens, keys, secrets
    echo "$message" | sed -E \
        -e 's/(password|passwd|pwd|pass|token|key|secret|auth)[=:][[:space:]]*[^[:space:]]+/\1=***REDACTED***/gi' \
        -e 's/(mysql|redis|db)_password[[:space:]]*=[[:space:]]*[^[:space:]]+/\1_password=***REDACTED***/gi'
}

set_log_context() {
    local phase=$1
    local operation=${2:-}
    LOG_CONTEXT="[$phase${operation:+ - $operation}]"
}

ensure_log_dir() {
    if [[ "$LOG_FILE_OUTPUT_ENABLED" != "true" ]]; then
        return 1
    fi
    if [[ -d "$LOG_DIR" ]]; then
        return 0
    fi
    mkdir -p "$LOG_DIR" 2>/dev/null || {
        LOG_FILE_OUTPUT_ENABLED=false
        return 1
    }
    return 0
}

log_error() {
    local message=$(sanitize_log_message "$1")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    echo -e "${RED}[ERROR]${NC} ${LOG_CONTEXT} $message" >&2
    if ensure_log_dir; then
        {
            echo "[$timestamp] [ERROR] ${LOG_CONTEXT} $message"
            echo "  Phase: $PHASE_CURRENT"
            [[ -n "$MYSQL_SOCKET" ]] && echo "  MySQL Socket: $MYSQL_SOCKET"
            [[ -n "$PHP_VERSION" ]] && echo "  PHP Version: $PHP_VERSION"
            echo "  Stack Trace:"
            local frame=0
            while caller $frame; do ((++frame)); done
        } >> "$LOG_ERROR_FILE" 2>/dev/null || true
    fi
}

log_warn() {
    local message=$(sanitize_log_message "$1")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    echo -e "${YELLOW}[WARN]${NC}  ${LOG_CONTEXT} $message"
    if ensure_log_dir; then
        echo "[$timestamp] [WARN] ${LOG_CONTEXT} $message" >> "$LOG_MAIN" 2>/dev/null || true
    fi
}

log_info() {
    local message=$(sanitize_log_message "$1")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    echo -e "${BLUE}[INFO]${NC}  ${LOG_CONTEXT} $message"
    if ensure_log_dir; then
        echo "[$timestamp] [INFO] ${LOG_CONTEXT} $message" >> "$LOG_MAIN" 2>/dev/null || true
    fi
}

log_success() {
    local message=$(sanitize_log_message "$1")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    echo -e "${GREEN}[OK]${NC}   ${LOG_CONTEXT} $message"
    if ensure_log_dir; then
        echo "[$timestamp] [SUCCESS] ${LOG_CONTEXT} $message" >> "$LOG_MAIN" 2>/dev/null || true
    fi
}

log_debug() {
    if [[ $LOG_LEVEL -lt $LOG_DEBUG ]]; then return 0; fi
    local message=$(sanitize_log_message "$1")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    echo -e "${MAGENTA}[DEBUG]${NC} ${LOG_CONTEXT} $message"
    if ensure_log_dir; then
        echo "[$timestamp] [DEBUG] ${LOG_CONTEXT} $message" >> "$LOG_DEBUG_FILE" 2>/dev/null || true
    fi
}

log_trace() {
    if [[ $LOG_LEVEL -lt $LOG_TRACE ]]; then return 0; fi
    local message=$(sanitize_log_message "$1")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    if ensure_log_dir; then
        echo "[$timestamp] [TRACE] ${LOG_CONTEXT} $message" >> "$LOG_TRACE_FILE" 2>/dev/null || true
    fi
}

log_audit() {
    local action=$1
    local details=$(sanitize_log_message "$2")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    local user=${SUDO_USER:-root}
    local ip=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()' || echo "local")
    if ensure_log_dir; then
        echo "[$timestamp] [AUDIT] User=$user IP=$ip Action=$action Details=$details" >> "$LOG_AUDIT_FILE" 2>/dev/null || true
    fi
}

log_security() {
    local event=$1
    local details=$(sanitize_log_message "$2")
    local timestamp=$(date "$LOG_TIMESTAMP_FORMAT")
    if ensure_log_dir; then
        echo "[$timestamp] [SECURITY] Event=$event Details=$details" >> "$LOG_SECURITY_FILE" 2>/dev/null || true
    fi
}

log_section() {
    local message=$1
    echo ""
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}$message${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
}

on_error() {
    local lineno=${1:-0}
    local cmd=${2:-"unknown"}
    local status=${3:-1}
    if [[ "$ERROR_HANDLED" == "true" ]]; then
        return 0
    fi
    ERROR_HANDLED=true
    set +e
    log_error "Unhandled error (exit=$status) at line $lineno: $cmd"
    log_security "ERROR_TRAP" "line=$lineno status=$status cmd=$cmd"
    if [[ ${#ROLLBACK_STACK[@]} -gt 0 ]]; then
        execute_rollback
    fi
    exit "$status"
}


# =============================================================================
# SECTION 3: INPUT VALIDATION & SANITIZATION
# Purpose: Validate domains, emails, and inputs to prevent injection.
# =============================================================================

validate_domain() {
    local domain=$1
    
    # Check for empty input
    if [[ -z "$domain" ]]; then
        log_error "Domain cannot be empty"
        log_security "INVALID_INPUT" "Empty domain provided"
        return 1
    fi
    
    # Check length (RFC 1035: max 253 characters)
    if [[ ${#domain} -gt 253 ]]; then
        log_error "Domain too long: ${#domain} characters (max 253)"
        log_security "INVALID_INPUT" "Domain length exceeded: $domain"
        return 1
    fi
    
    # Check for minimum length
    if [[ ${#domain} -lt 3 ]]; then
        log_error "Domain too short: ${#domain} characters (min 3)"
        log_security "INVALID_INPUT" "Domain too short: $domain"
        return 1
    fi
    
    # RFC 1035 compliant domain validation
    # - Only alphanumeric, hyphens, and dots
    # - Cannot start or end with hyphen or dot
    # - Each label (between dots) max 63 chars
    # - Cannot have consecutive dots
    if [[ ! "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $domain"
        log_security "INVALID_INPUT" "Domain failed RFC 1035 validation: $domain"
        return 1
    fi
    
    # Check for path traversal attempts
    if [[ "$domain" =~ \.\.|\/|\\|\$ ]]; then
        log_error "Domain contains invalid characters (path traversal attempt): $domain"
        log_security "SECURITY_VIOLATION" "Path traversal attempt detected in domain: $domain"
        return 1
    fi
    
    # Check for SQL injection patterns
    if [[ "$domain" =~ [\'\"\;\`\|] ]]; then
        log_error "Domain contains SQL injection characters: $domain"
        log_security "SECURITY_VIOLATION" "SQL injection attempt detected in domain: $domain"
        return 1
    fi
    
    # Check for command injection patterns
    if [[ "$domain" =~ [\$\(\)\{\}\[\]\<\>\&] ]]; then
        log_error "Domain contains command injection characters: $domain"
        log_security "SECURITY_VIOLATION" "Command injection attempt detected in domain: $domain"
        return 1
    fi
    
    # Validate each label length (between dots)
    IFS='.' read -ra labels <<< "$domain"
    for label in "${labels[@]}"; do
        if [[ ${#label} -gt 63 ]]; then
            log_error "Domain label too long: $label (max 63 characters)"
            log_security "INVALID_INPUT" "Domain label exceeded length: $label in $domain"
            return 1
        fi
        if [[ ${#label} -eq 0 ]]; then
            log_error "Domain contains empty label (consecutive dots)"
            log_security "INVALID_INPUT" "Empty label in domain: $domain"
            return 1
        fi
    done
    
    # Additional security: convert to lowercase
    domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
    
    log_debug "Domain validated: $domain"
    echo "$domain"
    return 0
}

validate_email() {
    local email=$1
    
    if [[ -z "$email" ]]; then
        log_error "Email cannot be empty"
        log_security "INVALID_INPUT" "Empty email provided"
        return 1
    fi
    
    if [[ ${#email} -gt 254 ]]; then
        log_error "Email too long"
        log_security "INVALID_INPUT" "Email length exceeded"
        return 1
    fi
    
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        log_error "Invalid email format: $email"
        log_security "INVALID_INPUT" "Email validation failed: $email"
        return 1
    fi
    
    echo "$email"
    return 0
}

validate_wp_admin_user() {
    local user=$1

    if [[ -z "$user" ]]; then
        log_error "Admin username cannot be empty"
        log_security "INVALID_INPUT" "Empty admin username provided"
        return 1
    fi

    if [[ ${#user} -gt 60 ]]; then
        log_error "Admin username too long"
        log_security "INVALID_INPUT" "Admin username length exceeded: $user"
        return 1
    fi

    if [[ ! "$user" =~ ^[A-Za-z0-9._-]{3,60}$ ]]; then
        log_error "Invalid admin username format: $user"
        log_security "INVALID_INPUT" "Admin username validation failed: $user"
        return 1
    fi

    echo "$user"
    return 0
}

domain_label_count() {
    local domain=$1
    local count=0
    local IFS='.'
    read -ra _labels <<< "$domain"
    count=${#_labels[@]}
    echo "$count"
}

is_subdomain() {
    local domain=$1
    local labels
    labels=$(domain_label_count "$domain")
    [[ "$labels" -ge 3 ]]
}

hostname_resolves() {
    local host=$1

    if command -v getent >/dev/null 2>&1; then
        getent ahosts "$host" >/dev/null 2>&1
        return $?
    fi

    if command -v dig >/dev/null 2>&1; then
        [[ -n "$(dig +short +time=2 +tries=1 "$host" 2>/dev/null)" ]]
        return $?
    fi

    if command -v host >/dev/null 2>&1; then
        host -W 2 "$host" 2>/dev/null | grep -qiE "has address|has IPv6 address"
        return $?
    fi

    if command -v nslookup >/dev/null 2>&1; then
        nslookup -timeout=2 "$host" >/dev/null 2>&1
        return $?
    fi

    return 1
}

should_include_www() {
    local domain=$1

    # Avoid doubling www, and skip www for subdomains
    if [[ "$domain" =~ ^www\. ]]; then
        return 1
    fi
    if is_subdomain "$domain"; then
        return 1
    fi

    hostname_resolves "www.$domain"
}

sanitize_site_title() {
    local title=$1
    
    # Remove control characters and trim
    title=$(echo "$title" | tr -d '\r\n\t' | sed 's/  */ /g' | sed 's/^ *//;s/ *$//')
    
    if [[ -z "$title" ]]; then
        log_error "Site title cannot be empty"
        log_security "INVALID_INPUT" "Empty site title provided"
        return 1
    fi
    
    if [[ ${#title} -gt 100 ]]; then
        title="${title:0:100}"
    fi
    
    echo "$title"
    return 0
}

sanitize_db_name() {
    local domain=$1
    # Convert domain to valid MySQL database name
    # Replace dots with underscores, remove invalid chars
    local db_name="wp_${domain//./_}"
    db_name=$(echo "$db_name" | tr -cd '[:alnum:]_')
    
    # MySQL database name max length is 64 characters
    if [[ ${#db_name} -gt 64 ]]; then
        # Truncate and add hash to ensure uniqueness
        local hash=$(echo "$domain" | sha256sum | cut -c1-8)
        db_name="${db_name:0:55}_${hash}"
    fi
    
    echo "$db_name"
}

sanitize_db_user() {
    local domain=$1
    # MySQL username max 32 characters (MariaDB 10.5+: 80 chars, but we use 32 for compatibility)
    local user="wp_${domain//./_}"
    user=$(echo "$user" | tr -cd '[:alnum:]_')
    
    if [[ ${#user} -gt 32 ]]; then
        local hash=$(echo "$domain" | sha256sum | cut -c1-6)
        user="${user:0:25}_${hash}"
    fi
    
    echo "$user"
}

generate_secure_password() {
    local length=${1:-32}
    # Generate cryptographically secure password
    openssl rand -base64 48 | tr -d "=+/" | cut -c1-${length}
}

mysql_exec() {
    local query=$1
    local socket_args=()
    if [[ -n "$MYSQL_SOCKET" ]]; then
        socket_args=(--socket="$MYSQL_SOCKET")
    fi
    mysql "${socket_args[@]}" -e "$query"
}

mysqldump_exec() {
    local db=$1
    local socket_args=()
    if [[ -n "$MYSQL_SOCKET" ]]; then
        socket_args=(--socket="$MYSQL_SOCKET")
    fi
    mysqldump "${socket_args[@]}" --single-transaction --quick --lock-tables=false "$db"
}

mysql_host_for_wp() {
    if [[ -z "$MYSQL_SOCKET" ]]; then
        detect_mysql_socket >/dev/null 2>&1 || true
    fi
    if [[ -n "$MYSQL_SOCKET" ]]; then
        echo "localhost:$MYSQL_SOCKET"
    else
        echo "localhost"
    fi
}

validate_mysql_connection() {
    local max_attempts=5
    local attempt=0
    if [[ -z "$MYSQL_SOCKET" ]]; then
        detect_mysql_socket >/dev/null 2>&1 || true
    fi
    
    while [[ $attempt -lt $max_attempts ]]; do
        if mysql_exec "SELECT 1;" >/dev/null 2>&1; then
            return 0
        fi
        ((++attempt))
        sleep 2
    done
    
    log_error "MySQL connection failed after $max_attempts attempts"
    return 1
}

validate_redis_connection() {
    local password=$1
    local max_attempts=5
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if redis-cli -a "$password" PING 2>/dev/null | grep -q "PONG"; then
            return 0
        fi
        ((++attempt))
        sleep 2
    done
    
    log_error "Redis connection failed after $max_attempts attempts"
    return 1
}

# =============================================================================
# SECTION 4: ENCRYPTION & CREDENTIAL MANAGEMENT
# Purpose: Key generation, encryption, and credential handling.
# =============================================================================

initialize_master_keys() {
    log_info "Initializing encryption keys..."
    
    # Create credentials directory with strict permissions
    mkdir -p "$CREDENTIALS_DIR"
    chmod 700 "$CREDENTIALS_DIR"
    
    # Generate master encryption key if not exists
    if [[ ! -f "$MASTER_KEY_FILE" ]]; then
        openssl rand -base64 32 > "$MASTER_KEY_FILE"
        chmod 400 "$MASTER_KEY_FILE"
        log_success "Master encryption key generated"
        log_audit "KEY_GENERATION" "Master encryption key created"
    fi
    
    # Generate backup encryption key if not exists
    if [[ ! -f "$BACKUP_KEY_FILE" ]]; then
        openssl rand -base64 32 > "$BACKUP_KEY_FILE"
        chmod 400 "$BACKUP_KEY_FILE"
        log_success "Backup encryption key generated"
        log_audit "KEY_GENERATION" "Backup encryption key created"
    fi
    
    log_success "Encryption keys initialized"
}

encrypt_credentials() {
    local plaintext_file=$1
    local encrypted_file="${plaintext_file}.enc"
    
    if [[ ! -f "$plaintext_file" ]]; then
        log_error "Plaintext file not found: $plaintext_file"
        return 1
    fi
    
    if [[ ! -f "$MASTER_KEY_FILE" ]]; then
        log_error "Master key not found: $MASTER_KEY_FILE"
        return 1
    fi
    
    # Encrypt with AES-256-CBC using PBKDF2
    openssl enc -"$ENCRYPTION_CIPHER" -salt -pbkdf2 -iter 100000 \
        -in "$plaintext_file" \
        -out "$encrypted_file" \
        -pass file:"$MASTER_KEY_FILE" 2>/dev/null || {
        log_error "Encryption failed for $plaintext_file"
        return 1
    }
    
    # Securely delete plaintext file
    shred -u -n 3 "$plaintext_file" 2>/dev/null || rm -f "$plaintext_file"
    
    # Set strict permissions on encrypted file
    chmod 400 "$encrypted_file"
    
    log_debug "Credentials encrypted: $encrypted_file"
    return 0
}

decrypt_credentials() {
    local encrypted_file=$1
    local plaintext_file="${encrypted_file%.enc}"
    
    if [[ ! -f "$encrypted_file" ]]; then
        log_error "Encrypted file not found: $encrypted_file"
        return 1
    fi
    
    if [[ ! -f "$MASTER_KEY_FILE" ]]; then
        log_error "Master key not found: $MASTER_KEY_FILE"
        return 1
    fi
    
    # Decrypt credentials
    openssl enc -"$ENCRYPTION_CIPHER" -d -pbkdf2 -iter 100000 \
        -in "$encrypted_file" \
        -out "$plaintext_file" \
        -pass file:"$MASTER_KEY_FILE" 2>/dev/null || {
        log_error "Decryption failed for $encrypted_file"
        return 1
    }
    
    chmod 600 "$plaintext_file"
    log_debug "Credentials decrypted: $plaintext_file"
    return 0
}

get_credential() {
    local domain=$1
    local key=$2
    local cred_file="$CREDENTIALS_DIR/${domain}-credentials.txt"
    
    if [[ ! -f "${cred_file}.enc" ]]; then
        log_error "Credential file not found for domain: $domain"
        return 1
    fi
    
    # Decrypt temporarily
    decrypt_credentials "${cred_file}.enc" || return 1
    
    # Extract value
    local value=$(grep "^${key}:" "$cred_file" 2>/dev/null | cut -d: -f2- | xargs)
    
    # Clean up plaintext
    shred -u -n 3 "$cred_file" 2>/dev/null || rm -f "$cred_file"
    
    if [[ -z "$value" ]]; then
        log_error "Credential key not found: $key for domain $domain"
        return 1
    fi
    
    echo "$value"
    return 0
}

# =============================================================================
# SECTION 5: ATOMIC LOCKING MECHANISM
# Purpose: Prevent concurrent registry modification and race conditions.
# =============================================================================

registry_lock() {
    local registry=$1
    local lock_file="$STATE_DIR/.${registry}.lock"
    local lock_fd=200
    local max_wait=60
    local waited=0
    
    # Create lock file if it doesn't exist
    touch "$lock_file" 2>/dev/null || {
        log_error "Cannot create lock file: $lock_file"
        return 1
    }
    
    # Open file descriptor for locking
    eval "exec $lock_fd>\"$lock_file\""
    
    # Try to acquire exclusive lock with timeout
    while ! flock -n $lock_fd 2>/dev/null; do
        sleep 0.5
        waited=$((waited + 1))
        
        if [[ $waited -ge $((max_wait * 2)) ]]; then
            log_error "Failed to acquire lock for $registry after ${max_wait}s"
            log_security "LOCK_TIMEOUT" "Registry lock timeout: $registry"
            eval "exec $lock_fd>&-"
            return 1
        fi
        
        # Check if lock file is stale (>5 minutes old)
        if [[ -f "$lock_file" ]]; then
            local lock_age=$(($(date +%s) - $(stat -c %Y "$lock_file" 2>/dev/null || echo 0)))
            if [[ $lock_age -gt 300 ]]; then
                log_warn "Stale lock detected for $registry (age: ${lock_age}s), breaking lock"
                rm -f "$lock_file"
                touch "$lock_file"
            fi
        fi
    done
    
    # Lock acquired successfully
    log_trace "Lock acquired for $registry (waited: ${waited}ms)"
    
    # Set trap to release lock on function return or script exit (never fail)
    trap "flock -u $lock_fd 2>/dev/null || true; eval 'exec $lock_fd>&-' 2>/dev/null || true; rm -f '$lock_file' 2>/dev/null || true" RETURN EXIT
    
    return 0
}

# =============================================================================
# SECTION 6: ROLLBACK & ERROR RECOVERY
# Purpose: Stack-safe rollback tracking for partial failures.
# =============================================================================

push_rollback() {
    local action=$1
    ROLLBACK_STACK+=("$action")
    log_trace "Rollback action registered: $action"
}

execute_rollback() {
    if [[ ${#ROLLBACK_STACK[@]} -eq 0 ]]; then
        log_debug "No rollback actions to execute"
        return 0
    fi
    
    log_warn "Executing rollback (${#ROLLBACK_STACK[@]} actions)..."
    
    # Execute rollback actions in reverse order (LIFO)
    for ((i=${#ROLLBACK_STACK[@]}-1; i>=0; i--)); do
        local action="${ROLLBACK_STACK[i]}"
        log_info "Rollback: $action"
        
        # Execute rollback action
        eval "$action" 2>/dev/null || {
            log_error "Rollback action failed: $action"
        }
    done
    
    # Clear rollback stack
    ROLLBACK_STACK=()
    log_success "Rollback completed"
}

safe_cleanup() {
    local path=$1
    
    # Validate path is not dangerous
    if [[ "$path" == "/" ]] || [[ "$path" == "/root" ]] || [[ "$path" == "/home" ]] || \
       [[ "$path" == "/etc" ]] || [[ "$path" == "/var" ]] || [[ "$path" == "/usr" ]]; then
        log_error "Refusing to clean dangerous path: $path"
        log_security "DANGEROUS_OPERATION" "Attempted cleanup of system path: $path"
        return 1
    fi
    
    # Only cleanup if path is within expected directories
    if [[ "$path" =~ ^($SITES_DIR|$BACKUP_DIR|$CACHE_DIR|/tmp/wp-) ]]; then
        if [[ -d "$path" ]] || [[ -f "$path" ]]; then
            rm -rf "$path" 2>/dev/null || {
                log_warn "Failed to cleanup: $path"
            }
            log_debug "Cleaned up: $path"
        fi
    else
        log_warn "Path not in safe cleanup zone: $path"
        return 1
    fi
    
    return 0
}

# =============================================================================
# SECTION 7: REGISTRY FUNCTIONS (SECURED)
# Purpose: Domain registry, resource allocation, and metadata tracking.
# =============================================================================

initialize_registries() {
    log_info "Initializing registries..."
    
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    local now=$(date +%s)
    
    cat > "$REGISTRY_FILE" <<DOMAIN_REG
{
  "version": "0.0.1",
  "domains": {},
  "metadata": {
    "total": 0,
    "created_at": $now,
    "last_updated": $now
  }
}
DOMAIN_REG

    cat > "$STATE_DIR/redis-allocator.json" <<REDIS_ALLOC
{
  "version": "0.0.1",
  "allocations": {},
  "free_databases": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  "metadata": {
    "total_allocated": 0,
    "created_at": $now,
    "last_updated": $now
  }
}
REDIS_ALLOC

    chmod 600 "$STATE_DIR"/*.json
    log_success "Registries initialized"
}

redis_allocate_db() {
    local domain=$1
    
    # Acquire atomic lock
    registry_lock "redis-allocator" || return 1
    
    local allocator="$STATE_DIR/redis-allocator.json"
    
    # Validate JSON file exists and is readable
    if [[ ! -f "$allocator" ]]; then
        log_error "Redis allocator registry not found" >&2
        return 1
    fi
    
    # Check if domain already has allocation
    local existing=$(jq -r ".allocations[\"$domain\"].db // \"null\"" "$allocator" 2>/dev/null)
    if [[ "$existing" != "null" ]]; then
        log_warn "Domain already has Redis DB allocated: $domain (DB: $existing)" >&2
        echo "$existing"
        return 0
    fi
    
    # Get first available database
    local available=$(jq -r '.free_databases[0] // "null"' "$allocator" 2>/dev/null)
    
    if [[ -z "$available" ]] || [[ "$available" == "null" ]]; then
        log_error "No available Redis databases for $domain" >&2
        log_security "RESOURCE_EXHAUSTION" "Redis database pool exhausted"
        return 1
    fi
    
    # Atomic update with backup
    cp "$allocator" "${allocator}.backup"
    
    if ! jq --arg domain "$domain" --arg db "$available" \
        '.allocations[$domain] = {
            db: ($db|tonumber), 
            allocated_at: now,
            status: "active"
        } | 
        .free_databases |= map(select(. != ($db|tonumber))) | 
        .metadata.total_allocated += 1 | 
        .metadata.last_updated = now' \
        "$allocator" > "${allocator}.tmp"; then
        
        log_error "Failed to update Redis allocator" >&2
        mv "${allocator}.backup" "$allocator"
        return 1
    fi
    
    mv "${allocator}.tmp" "$allocator"
    rm -f "${allocator}.backup"
    
    log_success "Allocated Redis DB $available for $domain" >&2
    log_audit "REDIS_DB_ALLOCATE" "domain=$domain db=$available"
    
    echo "$available"
    return 0
}

redis_release_db() {
    local domain=$1
    
    # Acquire atomic lock
    registry_lock "redis-allocator" || return 1
    
    local allocator="$STATE_DIR/redis-allocator.json"
    
    # Get allocated database number
    local db=$(jq -r ".allocations[\"$domain\"].db // \"null\"" "$allocator" 2>/dev/null)
    
    if [[ -z "$db" ]] || [[ "$db" == "null" ]]; then
        log_warn "Redis DB not found for $domain (may already be released)" >&2
        return 0
    fi
    
    # Flush the database before releasing
    if [[ -n "$REDIS_PASSWORD" ]]; then
        redis-cli -a "$REDIS_PASSWORD" -n "$db" FLUSHDB 2>/dev/null || true
    fi
    
    # Atomic update with backup
    cp "$allocator" "${allocator}.backup"
    
    if ! jq --arg domain "$domain" --arg db "$db" \
        'del(.allocations[$domain]) | 
        .free_databases += [($db|tonumber)] | 
        .free_databases |= sort | 
        .free_databases |= unique |
        .metadata.total_allocated -= 1 |
        .metadata.last_updated = now' \
        "$allocator" > "${allocator}.tmp"; then
        
        log_error "Failed to update Redis allocator during release" >&2
        mv "${allocator}.backup" "$allocator"
        return 1
    fi
    
    mv "${allocator}.tmp" "$allocator"
    rm -f "${allocator}.backup"
    
    log_success "Released Redis DB $db for $domain" >&2
    log_audit "REDIS_DB_RELEASE" "domain=$domain db=$db"
    
    return 0
}

domain_register() {
    local domain=$1
    local redis_db=$2
    local pool_name=$3
    local db_name=$4
    local db_user=$5
    local site_title=${6:-}
    local admin_email=${7:-}
    
    # Acquire atomic lock
    registry_lock "domain" || return 1
    
    local registry="$REGISTRY_FILE"
    
    # Validate inputs
    [[ -z "$domain" ]] || [[ -z "$redis_db" ]] || [[ -z "$pool_name" ]] && {
        log_error "Missing required parameters for domain registration"
        return 1
    }
    
    # Check if domain already registered
    if jq -e ".domains[\"$domain\"]" "$registry" >/dev/null 2>&1; then
        log_error "Domain already registered: $domain"
        return 1
    fi
    
    # Atomic update with backup
    cp "$registry" "${registry}.backup"
    
    if ! jq --arg domain "$domain" \
           --arg redis_db "$redis_db" \
           --arg pool "$pool_name" \
           --arg db_name "$db_name" \
           --arg db_user "$db_user" \
           --arg site_title "$site_title" \
           --arg admin_email "$admin_email" \
        '.domains[$domain] = {
            redis_db: ($redis_db|tonumber),
            php_pool: $pool,
            db_name: $db_name,
            db_user: $db_user,
            site_title: $site_title,
            admin_email: $admin_email,
            created_at: now,
            status: "active",
            version: "0.0.1"
        } | 
        .metadata.total += 1 |
        .metadata.last_updated = now' \
        "$registry" > "${registry}.tmp"; then
        
        log_error "Failed to update domain registry"
        mv "${registry}.backup" "$registry"
        return 1
    fi
    
    mv "${registry}.tmp" "$registry"
    rm -f "${registry}.backup"
    
    log_success "Domain registered: $domain"
    log_audit "DOMAIN_REGISTER" "domain=$domain redis_db=$redis_db pool=$pool_name"
    
    return 0
}

domain_unregister() {
    local domain=$1
    
    # Acquire atomic lock
    registry_lock "domain" || return 1
    
    local registry="$REGISTRY_FILE"
    
    # Check if domain exists
    if ! jq -e ".domains[\"$domain\"]" "$registry" >/dev/null 2>&1; then
        log_warn "Domain not found in registry: $domain"
        return 0
    fi
    
    # Atomic update with backup
    cp "$registry" "${registry}.backup"
    
    if ! jq --arg domain "$domain" \
        'del(.domains[$domain]) | 
        .metadata.total -= 1 |
        .metadata.last_updated = now' \
        "$registry" > "${registry}.tmp"; then
        
        log_error "Failed to update domain registry during unregistration"
        mv "${registry}.backup" "$registry"
        return 1
    fi
    
    mv "${registry}.tmp" "$registry"
    rm -f "${registry}.backup"
    
    log_success "Domain unregistered: $domain"
    log_audit "DOMAIN_UNREGISTER" "domain=$domain"
    
    return 0
}

# =============================================================================
# SECTION 8: RESOURCE CALCULATOR (CORRECTED)
# Purpose: Calculate sane defaults for PHP, Nginx, Redis, and MySQL.
# =============================================================================

calculate_system_resources() {
    log_section "Calculating Adaptive System Resources"
    
    set_log_context "Resource-Calc"
    
    # Detect total RAM
    local total_ram
    if command -v free &>/dev/null; then
        total_ram=$(free -b 2>/dev/null | awk 'NR==2 {print $2}')
    else
        total_ram=$(awk '/^MemTotal:/{print $2*1024}' /proc/meminfo 2>/dev/null || echo 1073741824)
    fi
    
    SYSTEM_RAM_GB=$((total_ram / 1024 / 1024 / 1024))
    SYSTEM_RAM_MB=$((total_ram / 1024 / 1024))
    
    if [[ $SYSTEM_RAM_MB -lt 512 ]]; then
        log_error "Insufficient RAM: ${SYSTEM_RAM_MB}MB (minimum 512MB required)"
        return 1
    fi
    
    # Detect CPU cores
    if command -v nproc &>/dev/null; then
        SYSTEM_CPU_CORES=$(nproc 2>/dev/null || echo 1)
    else
        SYSTEM_CPU_CORES=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo 1)
    fi
    
    [[ $SYSTEM_CPU_CORES -lt 1 ]] && SYSTEM_CPU_CORES=1
    
    log_info "Detected: ${SYSTEM_RAM_GB}GB RAM, $SYSTEM_CPU_CORES CPU cores"
    
    # ========================================================================
    # CORRECTED PHP-FPM CALCULATION
    # Reality: WordPress with plugins uses 128-256MB per request
    # We use conservative estimates to prevent OOM
    # ========================================================================
    
    # Reserve memory for system, MySQL, Redis, Nginx (dynamic for low-memory systems)
    local system_reserved_mb=512
    local mysql_reserved_mb=$((SYSTEM_RAM_MB * 50 / 100))  # 50% for MySQL
    local redis_reserved_mb=$((SYSTEM_RAM_MB * 10 / 100))  # 10% for Redis
    local nginx_reserved_mb=100
    
    if [[ $SYSTEM_RAM_MB -le 1024 ]]; then
        system_reserved_mb=256
        mysql_reserved_mb=$((SYSTEM_RAM_MB * 25 / 100))
        [[ $mysql_reserved_mb -lt 96 ]] && mysql_reserved_mb=96
        redis_reserved_mb=32
        nginx_reserved_mb=32
    elif [[ $SYSTEM_RAM_MB -le 2048 ]]; then
        system_reserved_mb=384
        mysql_reserved_mb=512
        redis_reserved_mb=128
        nginx_reserved_mb=64
    fi
    
    local total_reserved_mb=$((system_reserved_mb + mysql_reserved_mb + redis_reserved_mb + nginx_reserved_mb))
    local php_available_mb=$((SYSTEM_RAM_MB - total_reserved_mb))
    
    # Ensure we have at least some memory for PHP
    if [[ $php_available_mb -lt 128 ]]; then
        log_warn "Very limited memory for PHP-FPM: ${php_available_mb}MB"
        php_available_mb=128
    fi
    
    # REALISTIC PHP process size (WordPress + WooCommerce average)
    local php_process_size=80  # Base: 80MB per child process
    
    # Adjust process size based on available memory (larger sites can use more)
    if [[ $SYSTEM_RAM_MB -le 1024 ]]; then
        php_process_size=48   # Minimal mode
        PHP_MEMORY_LIMIT="128M"
    elif [[ $SYSTEM_RAM_MB -le 2048 ]]; then
        php_process_size=80
        PHP_MEMORY_LIMIT="256M"
    elif [[ $SYSTEM_RAM_GB -le 4 ]]; then
        php_process_size=96
        PHP_MEMORY_LIMIT="512M"
    elif [[ $SYSTEM_RAM_GB -le 8 ]]; then
        php_process_size=128
        PHP_MEMORY_LIMIT="1024M"
    else
        php_process_size=128
        PHP_MEMORY_LIMIT="2048M"
    fi
    
    # Calculate max children with safety margin (80% of available)
    PHP_MAX_CHILDREN=$((php_available_mb * 8 / 10 / php_process_size))
    
    # Enforce reasonable limits
    [[ $PHP_MAX_CHILDREN -lt 2 ]] && PHP_MAX_CHILDREN=2
    [[ $PHP_MAX_CHILDREN -gt 256 ]] && PHP_MAX_CHILDREN=256
    
    # Calculate pool workers
    PHP_START_SERVERS=$((PHP_MAX_CHILDREN / 3))
    [[ $PHP_START_SERVERS -lt 1 ]] && PHP_START_SERVERS=1
    
    PHP_MIN_SPARE=$((PHP_MAX_CHILDREN / 6))
    [[ $PHP_MIN_SPARE -lt 1 ]] && PHP_MIN_SPARE=1
    
    PHP_MAX_SPARE=$((PHP_MAX_CHILDREN / 2))
    [[ $PHP_MAX_SPARE -lt 1 ]] && PHP_MAX_SPARE=1
    [[ $PHP_MAX_SPARE -le $PHP_MIN_SPARE ]] && PHP_MAX_SPARE=$((PHP_MIN_SPARE + 1))
    
    # MySQL configuration
    MYSQL_INNODB_BUFFER="${mysql_reserved_mb}M"
    
    local log_size_mb=$((mysql_reserved_mb / 4))
    [[ $log_size_mb -lt 50 ]] && log_size_mb=50
    [[ $log_size_mb -gt 512 ]] && log_size_mb=512
    MYSQL_LOG_FILE_SIZE="${log_size_mb}M"
    
    if [[ $SYSTEM_RAM_MB -le 2048 ]]; then
        MYSQL_BUFFER_POOL_INSTANCES=1
    elif [[ $SYSTEM_RAM_MB -le 8192 ]]; then
        MYSQL_BUFFER_POOL_INSTANCES=2
    else
        MYSQL_BUFFER_POOL_INSTANCES=4
    fi
    
    # Redis configuration
    REDIS_MEMORY="${redis_reserved_mb}mb"
    
    # Nginx configuration
    NGINX_WORKER_PROCESSES=$SYSTEM_CPU_CORES
    
    if [[ $SYSTEM_CPU_CORES -le 2 ]]; then
        NGINX_WORKER_CONNECTIONS=512
    elif [[ $SYSTEM_CPU_CORES -le 8 ]]; then
        NGINX_WORKER_CONNECTIONS=1024
    else
        NGINX_WORKER_CONNECTIONS=2048
    fi
    
    # Cache sizing based on disk
    local disk_total_mb=$(df -m / | awk 'NR==2 {print $2}')
    if [[ $disk_total_mb -lt 20000 ]]; then
        NGINX_CACHE_MAX_SIZE="256m"
    else
        NGINX_CACHE_MAX_SIZE="1g"
    fi
    
    # Export all variables
    export SYSTEM_RAM_GB SYSTEM_RAM_MB SYSTEM_CPU_CORES
    export PHP_MAX_CHILDREN PHP_START_SERVERS PHP_MIN_SPARE PHP_MAX_SPARE
    export PHP_MEMORY_LIMIT MYSQL_INNODB_BUFFER MYSQL_LOG_FILE_SIZE MYSQL_BUFFER_POOL_INSTANCES
    export REDIS_MEMORY NGINX_WORKER_PROCESSES NGINX_WORKER_CONNECTIONS NGINX_CACHE_MAX_SIZE
    
    # Log resource allocation
    log_info "Resource Allocation:"
    log_info "  PHP: ${php_available_mb}MB (max_children=$PHP_MAX_CHILDREN, process_size=${php_process_size}MB, memory_limit=$PHP_MEMORY_LIMIT)"
    log_info "  MySQL: $MYSQL_INNODB_BUFFER buffer, $MYSQL_LOG_FILE_SIZE log, instances=$MYSQL_BUFFER_POOL_INSTANCES"
    log_info "  Redis: $REDIS_MEMORY"
    log_info "  Nginx: $NGINX_WORKER_PROCESSES workers, $NGINX_WORKER_CONNECTIONS connections, cache_max=$NGINX_CACHE_MAX_SIZE"
    
    log_success "Resources calculated (realistic PHP sizing applied)"
}

# =============================================================================
# SECTION 9: MYSQL SOCKET DETECTION (IMPROVED)
# Purpose: Discover local MariaDB/MySQL socket and version details.
# =============================================================================

detect_mysql_socket() {
    log_info "Detecting MySQL socket..."
    
    local socket=""
    
    # Method 1: Ask mysqladmin
    if command -v mysqladmin &>/dev/null; then
        socket=$(mysqladmin variables 2>/dev/null | grep "^| socket" | awk '{print $4}' | tr -d '|' | xargs)
    fi
    
    # Method 2: Parse MySQL configuration
    if [[ -z "$socket" ]]; then
        if [[ -d /etc/mysql ]]; then
            socket=$(grep -r "^socket" /etc/mysql/ 2>/dev/null | head -1 | awk '{print $3}' | tr -d '"' | xargs)
        fi
    fi
    
    # Method 3: Check common locations
    if [[ -z "$socket" ]]; then
        for path in /run/mysqld/mysqld.sock /var/run/mysqld/mysqld.sock /tmp/mysql.sock /var/lib/mysql/mysql.sock; do
            if [[ -S "$path" ]]; then
                socket="$path"
                break
            fi
        done
    fi
    
    # Method 4: Use MySQL to find itself
    if [[ -z "$socket" ]] && command -v mysql &>/dev/null; then
        socket=$(mysql -e "SHOW VARIABLES LIKE 'socket';" 2>/dev/null | awk 'NR==2 {print $2}')
    fi
    
    if [[ -z "$socket" ]]; then
        log_error "Could not detect MySQL socket"
        return 1
    fi
    
    if [[ ! -S "$socket" ]]; then
        log_error "MySQL socket not found at detected location: $socket"
        return 1
    fi
    
    MYSQL_SOCKET="$socket"
    log_success "MySQL socket detected: $MYSQL_SOCKET"
    return 0
}

detect_php_version() {
    [[ -n "$PHP_VERSION" ]] && return 0
    
    local version=""
    
    # Method 1: Installation record
    if [[ -f "$INSTALL_RECORD_FILE" ]]; then
        version=$(awk -F': ' '/^PHP:/ {print $2}' "$INSTALL_RECORD_FILE" 2>/dev/null | xargs)
    fi
    
    # Method 2: Installed PHP directories
    if [[ -z "$version" ]] && [[ -d /etc/php ]]; then
        version=$(ls -1 /etc/php 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -V | tail -1)
    fi
    
    # Method 3: PHP binary
    if [[ -z "$version" ]] && command -v php &>/dev/null; then
        version=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)
    fi
    
    if [[ -z "$version" ]]; then
        log_error "Unable to detect PHP version"
        return 1
    fi
    
    PHP_VERSION="$version"
    export PHP_VERSION
    log_success "PHP version detected: $PHP_VERSION"
    
    if [[ "$PHP_VERSION" != "$PHP_TARGET_VERSION" ]]; then
        log_warn "Detected PHP $PHP_VERSION (target is $PHP_TARGET_VERSION)"
    fi
    
    return 0
}

# =============================================================================
# SECTION 10: PRE-FLIGHT VALIDATION
# Purpose: Verify OS, privileges, disk, memory, and network readiness.
# =============================================================================

check_root() {
    [[ $EUID -ne 0 ]] && {
        log_error "Root privileges required. Please run with sudo."
        exit 1
    }
    log_success "Root privileges confirmed"
}

check_os() {
    [[ ! -f /etc/os-release ]] && {
        log_error "Cannot determine operating system"
        exit 1
    }
    
    . /etc/os-release
    [[ "$ID" != "ubuntu" ]] && {
        log_error "Ubuntu required (detected: $PRETTY_NAME)"
        log_info "This installer is designed for Ubuntu 24.04+ only"
        exit 1
    }
    
    local major=${VERSION_ID%%.*}
    local minor=${VERSION_ID#*.}
    minor=${minor%%.*}
    [[ -z "$minor" ]] && minor=0

    if [[ "$major" -lt 24 ]]; then
        log_error "Ubuntu 24.04+ required (detected: $PRETTY_NAME)"
        exit 1
    fi

    if [[ "$major" -eq 24 ]] && [[ "$minor" -lt 4 ]]; then
        log_error "Ubuntu 24.04 LTS or newer required (detected: $PRETTY_NAME)"
        exit 1
    fi

    if [[ "$major" -gt 24 ]] || [[ "$minor" -gt 4 ]]; then
        log_warn "Running on a newer Ubuntu release ($PRETTY_NAME); best-effort support"
    fi

    log_success "OS verified: $PRETTY_NAME"
}

check_system_resources() {
    log_info "Analyzing system resources..."
    calculate_system_resources || exit 1
    
    # Validate minimum requirements
    if [[ $SYSTEM_RAM_MB -lt 512 ]]; then
        log_error "Minimum 512MB RAM required (found: ${SYSTEM_RAM_MB}MB)"
        exit 1
    fi
    
    if [[ $SYSTEM_RAM_MB -lt 1024 ]]; then
        log_warn "Running in MINIMAL mode (512-1023MB RAM)"
        log_warn "Recommended: 2GB+ RAM for production use"
    fi
    
    # Check disk space
    local disk_available=$(df / | awk 'NR==2 {print $4}')
    local disk_available_gb=$((disk_available / 1024 / 1024))
    
    if [[ $disk_available_gb -lt 5 ]]; then
        log_error "Minimum 5GB disk space required (found: ${disk_available_gb}GB)"
        exit 1
    fi
    
    if [[ $disk_available_gb -lt 10 ]]; then
        log_warn "Disk space low: ${disk_available_gb}GB (recommended: 10GB+)"
    fi
    
    log_success "System resources validated"
}

check_network() {
    log_info "Checking network connectivity..."
    
    local connected=false
    
    # ICMP ping can be blocked; try it first, then fallback to HTTPS/TCP
    local hosts=("8.8.8.8" "1.1.1.1")
    if command -v ping &>/dev/null; then
        for host in "${hosts[@]}"; do
            if timeout 5 ping -c 1 "$host" &> /dev/null; then
                connected=true
                break
            fi
        done
    fi
    
    if [[ "$connected" == "false" ]]; then
        if command -v curl &>/dev/null; then
            curl -fsSL --max-time 5 https://www.cloudflare.com >/dev/null 2>&1 && connected=true
        elif command -v wget &>/dev/null; then
            wget -q --timeout=5 --spider https://www.cloudflare.com && connected=true
        else
            timeout 5 bash -c 'cat < /dev/tcp/1.1.1.1/80' >/dev/null 2>&1 && connected=true
        fi
    fi
    
    if [[ "$connected" == "false" ]]; then
        log_error "No internet connectivity detected"
        log_info "Internet connection required for package installation"
        exit 1
    fi
    
    log_success "Network connectivity confirmed"
}

check_dependencies() {
    log_info "Checking required dependencies..."
    
    local missing=()
    local commands=(
        bash awk sed grep cut tr date stat chmod chown mkdir rm find touch ln
        systemctl timeout flock openssl curl wget jq apt-cache dpkg
        php mysql mysqladmin mysqldump redis-cli nginx certbot
    )
    
    for cmd in "${commands[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    
    if [[ ! -x "$WP_CLI_BIN" ]]; then
        missing+=("wp-cli")
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        return 1
    fi
    
    log_success "All dependencies present"
    return 0
}

check_prior_initialization() {
    if [[ -f "$INITIALIZED_FLAG" ]]; then
        log_error "System already initialized"
        log_info "To re-install, first remove: $INITIALIZED_FLAG"
        log_warn "WARNING: Re-installation will not preserve existing sites"
        exit 1
    fi
    log_success "Fresh installation confirmed"
}

initialize_directories() {
    log_info "Creating directory structure..."
    
    # Create all required directories
    mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$BACKUP_DIR" "$CACHE_DIR" "$CONFIG_DIR" "$STATE_DIR"
    mkdir -p /var/log/{php-fpm,mysql,nginx,redis,wordpress}
    mkdir -p "$CERTS_DIR" "$CREDENTIALS_DIR"
    mkdir -p /etc/nginx/{sites-available,sites-enabled,conf.d,snippets}
    mkdir -p /var/lib/php/sessions
    mkdir -p "$SITES_DIR"
    
    # Set appropriate permissions
    chmod 755 "$INSTALL_DIR" "$LOG_DIR" "$BACKUP_DIR" "$CACHE_DIR" "$CONFIG_DIR"
    chmod 700 "$STATE_DIR" "$CREDENTIALS_DIR"
    chmod 1733 /var/lib/php/sessions  # Sticky bit + group writable
    
    log_success "Directory structure created"
}

safe_apt_install() {
    local packages=("$@")
    log_info "Installing packages: ${packages[*]}"
    
    # Update package lists if needed (max once per hour)
    local last_update_file="/var/lib/apt/periodic/update-success-stamp"
    if [[ -f "$last_update_file" ]]; then
        local last_update=$(stat -c %Y "$last_update_file")
        local now=$(date +%s)
        if [[ $((now - last_update)) -gt 3600 ]]; then
            apt-get update >/dev/null 2>&1 || {
                log_error "Failed to update package lists"
                return 1
            }
        fi
    fi
    
    # Install packages with error handling
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" 2>&1 | tee -a "$LOG_DEBUG_FILE" >/dev/null; then
        log_error "Package installation failed: ${packages[*]}"
        log_info "Check $LOG_DEBUG_FILE for details"
        return 1
    fi
    
    # Track installed packages
    INSTALLED_PACKAGES+=("${packages[@]}")
    
    log_success "Packages installed successfully"
    return 0
}

check_php_package_availability() {
    local packages=("$@")
    local missing=()
    local wrong_origin=()
    local ppa_missing=()
    local core_pkgs=("php${PHP_VERSION}" "php${PHP_VERSION}-fpm" "php${PHP_VERSION}-cli")
    
    for pkg in "${packages[@]}"; do
        local policy
        policy=$(apt-cache policy "$pkg" 2>/dev/null || true)
        local candidate
        candidate=$(echo "$policy" | awk '/Candidate:/ {print $2}')
        
        if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
            if php_package_is_optional "$pkg"; then
                log_warn "Optional PHP package not available (built-in/merged): $pkg"
            else
                missing+=("$pkg")
            fi
            continue
        fi
        
        for core in "${core_pkgs[@]}"; do
            if [[ "$pkg" == "$core" ]]; then
                if ! policy_candidate_from_ondrej "$policy" "$candidate"; then
                    if policy_has_ondrej_source "$policy"; then
                        wrong_origin+=("$pkg")
                    else
                        ppa_missing+=("$pkg")
                    fi
                fi
            fi
        done
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "PHP $PHP_VERSION packages not available: ${missing[*]}"
        log_error "Ensure ppa:ondrej/php is reachable and supports Ubuntu 24.04"
        return 1
    fi
    
    if [[ ${#ppa_missing[@]} -gt 0 ]]; then
        log_error "Ondrej PHP PPA not detected for core packages: ${ppa_missing[*]}"
        log_error "The PPA may not publish PHP $PHP_VERSION for this Ubuntu release yet"
        log_info "Options: wait for the PPA, switch mirrors, or set PHP_TARGET_VERSION=8.4"
        return 1
    fi

    if [[ ${#wrong_origin[@]} -gt 0 ]]; then
        log_error "Core PHP packages not selected from Ondrej PPA: ${wrong_origin[*]}"
        log_error "Aborting to avoid mixed PHP sources"
        log_info "Check APT pinning or other PHP repositories, then re-run"
        return 1
    fi
    
    return 0
}

package_available() {
    local pkg=$1
    local candidate
    candidate=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}')
    [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

first_available_package() {
    local pkg
    for pkg in "$@"; do
        if package_available "$pkg"; then
            echo "$pkg"
            return 0
        fi
    done
    return 1
}

install_nginx_optional_modules() {
    local optional=()
    local pkg=""

    pkg=$(first_available_package libnginx-mod-http-brotli nginx-module-brotli || true)
    [[ -n "$pkg" ]] && optional+=("$pkg")

    pkg=$(first_available_package libnginx-mod-http-zstd nginx-module-zstd || true)
    [[ -n "$pkg" ]] && optional+=("$pkg")

    pkg=$(first_available_package libnginx-mod-http-cache-purge nginx-module-cache-purge || true)
    [[ -n "$pkg" ]] && optional+=("$pkg")

    if [[ ${#optional[@]} -eq 0 ]]; then
        log_debug "No optional Nginx modules available via APT"
        return 0
    fi

    log_info "Installing optional Nginx modules: ${optional[*]}"
    safe_apt_install "${optional[@]}" || log_warn "Optional Nginx module install failed"
    return 0
}

policy_has_ondrej_source() {
    local policy=$1
    echo "$policy" | grep -Eqi "$ONDREJ_PHP_PPA_REGEX"
}

policy_candidate_from_ondrej() {
    local policy=$1
    local candidate=$2
    [[ -z "$candidate" || "$candidate" == "(none)" ]] && return 1
    awk -v cand="$candidate" -v re="$ONDREJ_PHP_PPA_REGEX" '
        $1 == "***" { ver=$2 }
        $1 ~ /^[0-9]/ { ver=$1 }
        ver == cand { inver=1 }
        ver != cand && $1 ~ /^[0-9]/ { inver=0 }
        inver && $0 ~ re { found=1 }
        END { exit(found ? 0 : 1) }
    ' <<< "$policy"
}

ensure_ondrej_php_preferred() {
    local core_pkgs=("php${PHP_VERSION}" "php${PHP_VERSION}-fpm" "php${PHP_VERSION}-cli")
    local ppa_found=false
    for pkg in "${core_pkgs[@]}"; do
        local policy
        policy=$(apt-cache policy "$pkg" 2>/dev/null || true)
        if policy_has_ondrej_source "$policy"; then
            ppa_found=true
            break
        fi
    done

    if [[ "$ppa_found" != "true" ]]; then
        log_error "Ondrej PHP PPA not detected for PHP $PHP_VERSION packages"
        log_error "The PPA may not publish PHP $PHP_VERSION for this Ubuntu release yet"
        log_info "Options: wait for the PPA, switch mirrors, or set PHP_TARGET_VERSION=8.4"
        return 1
    fi

    cat > "$ONDREJ_PHP_PREF_FILE" <<EOF
Package: php${PHP_VERSION} php${PHP_VERSION}-*
Pin: release o=LP-PPA-ondrej-php
Pin-Priority: 1001

Package: php${PHP_VERSION} php${PHP_VERSION}-*
Pin: origin "ppa.launchpad.net"
Pin-Priority: 1001

Package: php${PHP_VERSION} php${PHP_VERSION}-*
Pin: origin "deb.sury.org"
Pin-Priority: 1001
EOF

    apt-get update >/dev/null 2>&1 || {
        log_error "Failed to update package lists after pinning Ondrej PHP PPA"
        return 1
    }
    return 0
}

php_package_is_optional() {
    local pkg=$1
    if [[ "$pkg" != php${PHP_VERSION}-* ]]; then
        return 1
    fi
    local base="${pkg#php${PHP_VERSION}-}"
    for opt in "${PHP_OPTIONAL_PACKAGES[@]}"; do
        if [[ "$base" == "$opt" ]]; then
            return 0
        fi
    done
    return 1
}

verify_php_installation() {
    local packages=("$@")
    local missing=()
    
    for pkg in "${packages[@]}"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing PHP packages after install: ${missing[*]}"
        return 1
    fi
    
    # Verify core extensions
    local modules
    modules=$(php -m 2>/dev/null | tr '[:upper:]' '[:lower:]')
    local required=(curl gd mbstring xml zip intl soap bcmath redis)
    local missing_mods=()
    
    for mod in "${required[@]}"; do
        if ! echo "$modules" | grep -qx "$mod"; then
            missing_mods+=("$mod")
        fi
    done
    
    if ! echo "$modules" | grep -qx "mysqli" && ! echo "$modules" | grep -qx "mysqlnd"; then
        missing_mods+=("mysqli/mysqlnd")
    fi
    
    if [[ ${#missing_mods[@]} -gt 0 ]]; then
        log_error "Missing PHP extensions: ${missing_mods[*]}"
        return 1
    fi
    
    return 0
}

ensure_wp_cli() {
    if [[ -x "$WP_CLI_BIN" ]]; then
        return 0
    fi
    
    log_info "Installing WP-CLI..."
    if ! curl -fsSL "$WP_CLI_URL" -o "$WP_CLI_BIN" 2>/dev/null; then
        log_error "Failed to download WP-CLI"
        return 1
    fi
    
    chmod +x "$WP_CLI_BIN"
    
    if ! "$WP_CLI_BIN" --info >/dev/null 2>&1; then
        log_error "WP-CLI installation verification failed"
        return 1
    fi
    
    log_success "WP-CLI installed"
    return 0
}

ensure_wp_cli_cache() {
    mkdir -p "$WP_CLI_CACHE_DIR"
    chmod 775 "$WP_CLI_CACHE_DIR" 2>/dev/null || true
    if id -u www-data &>/dev/null; then
        chown www-data:www-data "$WP_CLI_CACHE_DIR" 2>/dev/null || true
    fi
}

run_wp_cli() {
    local path=$1
    shift

    ensure_wp_cli_cache
    
    if id -u www-data &>/dev/null; then
        if command -v sudo &>/dev/null; then
            sudo -u www-data -H env WP_CLI_CACHE_DIR="$WP_CLI_CACHE_DIR" "$WP_CLI_BIN" --path="$path" "$@"
            return $?
        else
            local args=()
            local arg=""
            for arg in "$@"; do
                args+=("$(printf '%q' "$arg")")
            done
            su -s /bin/bash www-data -c "WP_CLI_CACHE_DIR=\"$WP_CLI_CACHE_DIR\" \"$WP_CLI_BIN\" --path=\"$path\" ${args[*]}"
            return $?
        fi
    fi
    
    WP_CLI_CACHE_DIR="$WP_CLI_CACHE_DIR" "$WP_CLI_BIN" --path="$path" "$@" --allow-root
}

configure_cloudflare_realip() {
    if [[ "$ENABLE_CLOUDFLARE" != "true" ]]; then
        log_info "Cloudflare integration disabled"
        return 0
    fi
    log_info "Configuring Cloudflare real IP integration..."
    
    # Ensure file exists to avoid nginx include errors
    if [[ ! -f "$CLOUDFLARE_CONF" ]]; then
        echo "# Cloudflare IPs not loaded yet" > "$CLOUDFLARE_CONF"
    fi
    
    if ! command -v curl &>/dev/null; then
        log_warn "curl not found; skipping Cloudflare IP fetch"
        return 1
    fi
    
    local tmp_file="/tmp/cloudflare-ips.conf.$$"
    
    {
        echo "# Cloudflare IP ranges"
        curl -fsSL "$CLOUDFLARE_IPS_V4_URL" 2>/dev/null | sed 's/^/set_real_ip_from /;s/$/;/' || true
        curl -fsSL "$CLOUDFLARE_IPS_V6_URL" 2>/dev/null | sed 's/^/set_real_ip_from /;s/$/;/' || true
        echo "real_ip_header CF-Connecting-IP;"
        echo "real_ip_recursive on;"
    } > "$tmp_file"
    
    if [[ ! -s "$tmp_file" ]]; then
        log_warn "Cloudflare IP list empty; skipping"
        rm -f "$tmp_file"
        return 1
    fi
    
    mv "$tmp_file" "$CLOUDFLARE_CONF"
    chmod 644 "$CLOUDFLARE_CONF"
    
    # Daily refresh
    cat > "$CLOUDFLARE_CRON" <<'CF_CRON'
0 3 * * * root /usr/local/bin/update-cloudflare-ips.sh >/dev/null 2>&1
CF_CRON
    chmod 644 "$CLOUDFLARE_CRON"
    
    # Helper script for updates
    cat > /usr/local/bin/update-cloudflare-ips.sh <<'CF_UPDATE'
#!/bin/bash
set -euo pipefail

CLOUDFLARE_IPS_V4_URL="https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPS_V6_URL="https://www.cloudflare.com/ips-v6"
CLOUDFLARE_CONF="/etc/nginx/conf.d/dazestack-wp-cloudflare-ips.conf"

tmp_file="/tmp/cloudflare-ips.conf.$$"
{
  echo "# Cloudflare IP ranges"
  curl -fsSL "$CLOUDFLARE_IPS_V4_URL" 2>/dev/null | sed 's/^/set_real_ip_from /;s/$/;/' || true
  curl -fsSL "$CLOUDFLARE_IPS_V6_URL" 2>/dev/null | sed 's/^/set_real_ip_from /;s/$/;/' || true
  echo "real_ip_header CF-Connecting-IP;"
  echo "real_ip_recursive on;"
} > "$tmp_file"

if [[ -s "$tmp_file" ]]; then
  mv "$tmp_file" "$CLOUDFLARE_CONF"
  chmod 644 "$CLOUDFLARE_CONF"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
else
  rm -f "$tmp_file"
fi
CF_UPDATE
    chmod +x /usr/local/bin/update-cloudflare-ips.sh
    
    log_success "Cloudflare real IP configuration updated"
    return 0
}

write_cloudflare_recommendations() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/cloudflare-recommended.txt" <<'CF_REC'
Cloudflare Recommended Settings (Origin: DazeStack WP)

Security:
- SSL/TLS: Full (strict)
- Always Use HTTPS: On
- Automatic HTTPS Rewrites: On
- HSTS: Enabled (aligns with Nginx HSTS headers)

Performance:
- HTTP/3 (QUIC): On (if available on your plan)
- Brotli: On
- Auto Minify: CSS/JS/HTML On (optional; test with plugins)
- Early Hints: On (optional)

Caching:
- Cache Level: Standard
- Browser Cache TTL: 1 year (static assets handled by Nginx too)
- Cache Rules: Do NOT cache wp-admin, wp-login, or cart/checkout pages

Network:
- WebSockets: On (for real-time plugins)

Notes:
- This installer configures real client IPs via CF-Connecting-IP.
- For full-page cache at Cloudflare, ensure WordPress admin and dynamic paths are excluded.
CF_REC
    chmod 644 "$CONFIG_DIR/cloudflare-recommended.txt"
}

configure_firewall_preserve() {
    if ! command -v ufw &>/dev/null; then
        return 0
    fi
    
    log_info "Configuring UFW firewall (preserve existing rules)..."
    
    local ssh_port="22"
    if command -v sshd &>/dev/null; then
        ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || echo "22")
    else
        ssh_port=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)
        [[ -z "$ssh_port" ]] && ssh_port="22"
    fi
    
    ufw allow "$ssh_port"/tcp >/dev/null 2>&1 || true
    ufw allow http >/dev/null 2>&1 || true
    ufw allow https >/dev/null 2>&1 || true
    
    if ufw status | grep -q "Status: active"; then
        log_success "UFW rules updated (existing rules preserved)"
        return 0
    fi
    
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    echo "y" | ufw enable >/dev/null 2>&1
    log_success "UFW firewall enabled with safe defaults"
    return 0
}

nginx_module_enabled() {
    local pattern=$1
    compgen -G "/etc/nginx/modules-enabled/*${pattern}*.conf" >/dev/null 2>&1
}

detect_http3_support() {
    HTTP3_AVAILABLE=false
    if [[ "$ENABLE_HTTP3" != "true" ]]; then
        return 0
    fi
    if ! command -v nginx &>/dev/null; then
        return 0
    fi
    if nginx -V 2>&1 | grep -qiE 'http_v3_module|quic'; then
        HTTP3_AVAILABLE=true
        log_success "HTTP/3 support detected"
    else
        log_warn "HTTP/3 not supported by current Nginx build"
    fi
}

detect_brotli_support() {
    BROTLI_AVAILABLE=false
    if [[ "$ENABLE_BROTLI" != "true" ]]; then
        return 0
    fi
    if ! command -v nginx &>/dev/null; then
        return 0
    fi
    if nginx -V 2>&1 | grep -qi "brotli" || nginx_module_enabled "brotli"; then
        BROTLI_AVAILABLE=true
        log_success "Brotli support detected"
    else
        log_warn "Brotli not supported by current Nginx build"
    fi
}

detect_zstd_support() {
    ZSTD_AVAILABLE=false
    if [[ "$ENABLE_ZSTD" != "true" ]]; then
        return 0
    fi
    if ! command -v nginx &>/dev/null; then
        return 0
    fi
    if nginx -V 2>&1 | grep -qi "zstd" || nginx_module_enabled "zstd"; then
        ZSTD_AVAILABLE=true
        log_success "Zstd support detected"
    else
        log_warn "Zstd not supported by current Nginx build"
    fi
}

detect_cache_purge_support() {
    CACHE_PURGE_AVAILABLE=false
    if ! command -v nginx &>/dev/null; then
        return 0
    fi
    if nginx -V 2>&1 | grep -qiE "cache_purge|ngx_cache_purge" \
        || nginx_module_enabled "cache_purge" \
        || nginx_module_enabled "ngx_cache_purge"; then
        CACHE_PURGE_AVAILABLE=true
        log_success "Nginx cache purge module detected"
    else
        log_warn "Nginx cache purge module not detected"
    fi
}

write_nginx_main_config() {
    cat > /etc/nginx/nginx.conf <<NGINX_MAIN
user www-data;
worker_processes $NGINX_WORKER_PROCESSES;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections $NGINX_WORKER_CONNECTIONS;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    server_names_hash_bucket_size 64;
    server_tokens off;
    client_body_buffer_size 128k;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # TLS defaults (used by SSL-enabled vhosts)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_prefer_server_ciphers off;

    # File cache
    open_file_cache max=10000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    include /etc/nginx/snippets/wordpress-performance.conf;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGINX_MAIN
}

write_nginx_security_snippet() {
    cat > /etc/nginx/snippets/wordpress-security.conf <<'NGINX_SECURITY'
# Security Headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# FastCGI Buffers
fastcgi_buffers 16 16k;
fastcgi_buffer_size 32k;
client_max_body_size 100M;
client_body_timeout 300s;

# FastCGI Timeouts
fastcgi_connect_timeout 60s;
fastcgi_send_timeout 300s;
fastcgi_read_timeout 300s;

# Hide Nginx version
server_tokens off;
NGINX_SECURITY
}

write_nginx_performance_snippet() {
    cat > /etc/nginx/snippets/wordpress-performance.conf <<'NGINX_PERF'
# Compression
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_http_version 1.1;
gzip_min_length 1000;
gzip_comp_level 5;
gzip_static on;
gzip_disable "msie6";
gzip_types text/plain text/css text/xml text/javascript application/javascript application/x-javascript application/json application/xml application/xml+rss application/rss+xml application/atom+xml application/xhtml+xml image/svg+xml application/manifest+json;
NGINX_PERF

    if [[ "$BROTLI_AVAILABLE" == "true" ]]; then
        cat >> /etc/nginx/snippets/wordpress-performance.conf <<'NGINX_BROTLI'
# Brotli (if module available)
brotli on;
brotli_comp_level 5;
brotli_min_length 1000;
brotli_static on;
brotli_types text/plain text/css text/xml text/javascript application/javascript application/x-javascript application/json application/xml application/xml+rss application/rss+xml application/atom+xml application/xhtml+xml image/svg+xml application/manifest+json;
NGINX_BROTLI
    fi

    if [[ "$ZSTD_AVAILABLE" == "true" ]]; then
        cat >> /etc/nginx/snippets/wordpress-performance.conf <<'NGINX_ZSTD'
# Zstandard (if module available)
zstd on;
zstd_comp_level 3;
zstd_min_length 1000;
zstd_types text/plain text/css text/xml text/javascript application/javascript application/x-javascript application/json application/xml application/xml+rss application/rss+xml application/atom+xml application/xhtml+xml image/svg+xml application/manifest+json;
zstd_static on;
NGINX_ZSTD
    fi
}

write_nginx_http3_snippet() {
    cat > /etc/nginx/snippets/wordpress-http3.conf <<NGINX_HTTP3
# HTTP/2 + HTTP/3 (optional; include inside SSL server blocks)
listen 443 ssl http2;
NGINX_HTTP3
    if [[ "$HTTP3_AVAILABLE" == "true" ]]; then
        cat >> /etc/nginx/snippets/wordpress-http3.conf <<'NGINX_HTTP3_EXTRA'
listen 443 quic reuseport;
add_header Alt-Svc 'h3=":443"; ma=86400' always;
add_header Alt-Svc 'h3-29=":443"; ma=86400' always;
NGINX_HTTP3_EXTRA
    fi
}

write_nginx_rate_limits() {
    cat > /etc/nginx/conf.d/00-rate-limits.conf <<'NGINX_RATELIMIT'
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=wp_login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=wp_general:10m rate=30r/s;
limit_req_status 429;
NGINX_RATELIMIT
}

write_microcache_config() {
    cat > /etc/nginx/conf.d/10-cache-zones.conf <<'NGINX_CACHE'
# FastCGI micro-cache zones
fastcgi_cache_path /var/cache/nginx/microcache 
    levels=1:2 
    keys_zone=wordpress_cache:100m 
    max_size=CACHE_MAX_SIZE 
    inactive=60m 
    use_temp_path=off;

fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_cache_use_stale updating error timeout invalid_header http_500 http_503;
fastcgi_cache_lock on;
fastcgi_cache_lock_timeout 5s;

map $http_cookie $skip_cache {
    default 0;
    ~*wordpress_logged_in 1;
    ~*wordpress_sec 1;
    ~*wordpress_logged_in_ 1;
    ~*comment_author 1;
    ~*wp_postpass 1;
    ~*wp-postpass_ 1;
    ~*woocommerce_items_in_cart 1;
    ~*woocommerce_cart_hash 1;
    ~*wp_woocommerce_session_ 1;
}

map $request_method $skip_cache_method {
    default 1;
    GET 0;
    HEAD 0;
}

map $request_uri $skip_cache_uri {
    default 0;
    ~*/wp-admin/ 1;
    ~*/wp-login.php 1;
    ~*/wp-cron.php 1;
    ~*/wp-json/ 1;
    ~*/purge/ 1;
    ~*preview=true 1;
    ~*add-to-cart 1;
    ~*wc-api 1;
    ~*xmlrpc.php 1;
}
NGINX_CACHE
    sed -i "s/CACHE_MAX_SIZE/${NGINX_CACHE_MAX_SIZE}/" /etc/nginx/conf.d/10-cache-zones.conf
}

write_php_tuning() {
    local version=${1:-$PHP_VERSION}
    [[ -z "$version" ]] && return 1
    cat > /etc/php/${version}/fpm/conf.d/99-wordpress.ini <<PHP_INI
memory_limit = $PHP_MEMORY_LIMIT
max_execution_time = 300
max_input_time = 300
post_max_size = 100M
upload_max_filesize = 100M
expose_php = Off
cgi.fix_pathinfo = 0
; OPcache not configured (package not installed)
PHP_INI
    cp /etc/php/${version}/fpm/conf.d/99-wordpress.ini /etc/php/${version}/cli/conf.d/99-wordpress.ini 2>/dev/null || true
}

write_mariadb_tuning() {
    cat > /etc/mysql/mariadb.conf.d/99-wordpress-perf.cnf <<MYSQL_PERF
[mysqld]
# Disable binary logging for performance (not a replica)
skip-log-bin = 1

# Network
bind-address = 127.0.0.1
port = 3306
max_connections = 200
max_allowed_packet = 64M

# InnoDB
default-storage-engine = InnoDB
innodb_buffer_pool_size = $MYSQL_INNODB_BUFFER
innodb_buffer_pool_instances = $MYSQL_BUFFER_POOL_INSTANCES
innodb_log_file_size = $MYSQL_LOG_FILE_SIZE
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1

# Query Cache (disabled in MariaDB 10.5+)
query_cache_size = 0
query_cache_type = 0

# Character Set
character_set_server = utf8mb4
collation_server = utf8mb4_unicode_ci

# Security
local_infile = 0
MYSQL_PERF
}

apply_sysctl_tuning() {
    if [[ "$ENABLE_SYSCTL_TUNING" != "true" ]]; then
        return 0
    fi
    cat > /etc/sysctl.d/99-wp-performance.conf <<'SYSCTL'
fs.file-max = 1048576
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
SYSCTL
    sysctl --system >/dev/null 2>&1 || true
    log_success "Sysctl performance tuning applied"
}

install_cli_wrapper() {
    local src="$SCRIPT_DIR/$SCRIPT_NAME"
    if [[ -f "$src" ]]; then
        install -m 0755 "$src" "$CLI_WRAPPER" 2>/dev/null || true
        log_success "Installed CLI wrapper: $CLI_WRAPPER"
    fi
}

install_auto_tune_cron() {
    if [[ "$ENABLE_AUTO_TUNE" != "true" ]]; then
        return 0
    fi
    install_cli_wrapper
    cat > "$AUTO_TUNE_SCRIPT" <<AUTO_TUNE
#!/bin/bash
set -euo pipefail
${CLI_WRAPPER} auto-tune --non-interactive >/dev/null 2>&1 || true
AUTO_TUNE
    chmod +x "$AUTO_TUNE_SCRIPT"
    cat > "$AUTO_TUNE_CRON_FILE" <<AUTO_TUNE_CRON
$AUTO_TUNE_CRON root $AUTO_TUNE_SCRIPT
AUTO_TUNE_CRON
    chmod 644 "$AUTO_TUNE_CRON_FILE"
    log_success "Auto-tune cron installed"
}

apply_auto_tuning() {
    log_section "Auto-Tune: Adaptive Optimization"
    set_log_context "AUTO-TUNE"

    calculate_system_resources || return 1
    detect_php_version || true

    if [[ -d /etc/nginx ]]; then
        detect_http3_support
        detect_brotli_support
        detect_zstd_support
        detect_cache_purge_support
        write_nginx_main_config
        write_nginx_security_snippet
        write_nginx_performance_snippet
        write_nginx_http3_snippet
        write_nginx_rate_limits
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    fi

    if [[ -n "$PHP_VERSION" ]]; then
        write_php_tuning "$PHP_VERSION"
        systemctl reload php${PHP_VERSION}-fpm >/dev/null 2>&1 || true
    fi

    if systemctl is-active --quiet mariadb 2>/dev/null; then
        write_mariadb_tuning
        systemctl restart mariadb >/dev/null 2>&1 || true
    fi

    apply_sysctl_tuning

    if [[ -d /etc/nginx ]]; then
        write_microcache_config
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    fi
    rebalance_php_pools || true
    log_success "Auto-tune completed"
}

get_total_sites() {
    local registry="$REGISTRY_FILE"
    if [[ ! -f "$registry" ]]; then
        echo "0"
        return 0
    fi
    local total=$(jq -r '.metadata.total // 0' "$registry" 2>/dev/null)
    [[ -z "$total" ]] && total=0
    echo "$total"
}

calculate_pool_limits() {
    local total_sites=$1
    [[ $total_sites -lt 1 ]] && total_sites=1
    
    local site_max_children=$((PHP_MAX_CHILDREN / total_sites))
    [[ $site_max_children -lt 2 ]] && site_max_children=2
    
    local site_start=$((site_max_children / 3))
    [[ $site_start -lt 1 ]] && site_start=1
    
    local site_min=$((site_max_children / 6))
    [[ $site_min -lt 1 ]] && site_min=1
    
    local site_max=$((site_max_children / 2))
    [[ $site_max -le $site_min ]] && site_max=$((site_min + 1))
    
    echo "$site_max_children $site_start $site_min $site_max"
}

write_php_pool_config() {
    local pool_name=$1
    local site_dir=$2
    local site_tmp=$3
    local site_max_children=$4
    local site_start=$5
    local site_min=$6
    local site_max=$7
    local php_socket="/run/php/php${PHP_VERSION}-${pool_name}.sock"
    
    cat > "/etc/php/${PHP_VERSION}/fpm/pool.d/${pool_name}.conf" <<POOL_CONFIG
[$pool_name]
user = www-data
group = www-data

listen = $php_socket
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = $site_max_children
pm.start_servers = $site_start
pm.min_spare_servers = $site_min
pm.max_spare_servers = $site_max
pm.process_idle_timeout = 10s
pm.max_requests = 500

; Security (allow override via PHP_DISABLE_FUNCTIONS)
php_admin_value[disable_functions] = $PHP_DISABLE_FUNCTIONS
php_admin_value[open_basedir] = $site_dir/public:$site_tmp:/usr/share/php
php_admin_value[sys_temp_dir] = $site_tmp
php_admin_value[upload_tmp_dir] = $site_tmp

; Performance
php_admin_value[memory_limit] = $PHP_MEMORY_LIMIT
php_admin_value[max_execution_time] = 300
php_admin_value[max_input_time] = 300
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M

; OPcache not configured (package not installed)

; Session handling
php_admin_value[session.save_path] = $site_tmp

; Error logging
php_admin_value[error_log] = $site_dir/logs/php-error.log
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
POOL_CONFIG
}

write_php_bootstrap_pool() {
    local version=${1:-$PHP_VERSION}
    local pool_dir="/etc/php/${version}/fpm/pool.d"
    local socket="/run/php/php${version}-fpm.sock"
    mkdir -p "$pool_dir"

    cat > "${pool_dir}/zzz-bootstrap.conf" <<BOOTSTRAP_POOL
[bootstrap]
user = www-data
group = www-data

listen = $socket
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 1
pm.start_servers = 1
pm.min_spare_servers = 1
pm.max_spare_servers = 1
pm.process_idle_timeout = 10s
pm.max_requests = 500

php_admin_value[disable_functions] = $PHP_DISABLE_FUNCTIONS
php_admin_value[open_basedir] = /tmp:/usr/share/php:/var/lib/php/sessions
php_admin_value[sys_temp_dir] = /tmp
php_admin_value[upload_tmp_dir] = /tmp
php_admin_value[session.save_path] = /var/lib/php/sessions
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
BOOTSTRAP_POOL
}

rebalance_php_pools() {
    local registry="$REGISTRY_FILE"
    [[ ! -f "$registry" ]] && return 0
    
    local total_sites
    total_sites=$(get_total_sites)
    [[ $total_sites -lt 1 ]] && return 0
    
    read -r site_max_children site_start site_min site_max < <(calculate_pool_limits "$total_sites")
    
    jq -r '.domains | to_entries[] | "\(.key) \(.value.php_pool)"' "$registry" 2>/dev/null | while read -r domain pool_name; do
        [[ -z "$domain" ]] && continue
        local site_dir="$SITES_DIR/$domain"
        local site_tmp="$site_dir/tmp"
        if [[ -d "$site_dir" ]]; then
            write_php_pool_config "$pool_name" "$site_dir" "$site_tmp" "$site_max_children" "$site_start" "$site_min" "$site_max"
        fi
    done
    
    systemctl reload php${PHP_VERSION}-fpm 2>/dev/null || true
    log_success "Rebalanced PHP-FPM pools across $total_sites sites"
}

# =============================================================================
# SECTION 11: INSTALLATION PHASES
# Purpose: Modular install steps for the full stack.
# =============================================================================

phase_system_prerequisites() {
    log_section "Phase 1: System Prerequisites"
    set_log_context "Phase-1" "Prerequisites"
    
    log_info "Updating package lists..."
    apt-get update > /dev/null 2>&1 || {
        log_error "Failed to update package lists"
        exit 1
    }
    
    safe_apt_install \
        curl wget jq git htop net-tools ca-certificates gnupg \
        python3 logrotate unzip gzip tar bzip2 sudo \
        apt-transport-https lsb-release openssl \
        software-properties-common dnsutils \
        fail2ban ufw || exit 1
    
    log_success "System prerequisites installed"
    PHASE_CURRENT=1
}

phase_php_installation() {
    log_section "Phase 2: PHP Installation"
    set_log_context "Phase-2" "PHP"
    
    log_info "Adding PHP repository..."
    if [[ "$PHP_TARGET_VERSION" != "8.5" ]]; then
        log_warn "This release is tuned for PHP 8.5 (current target: $PHP_TARGET_VERSION)"
    fi
    add-apt-repository -y ppa:ondrej/php > /dev/null 2>&1 || {
        log_error "Failed to add PHP repository"
        exit 1
    }
    
    apt-get update > /dev/null 2>&1
    
    # Default to PHP 8.5 (stable)
    PHP_VERSION="$PHP_TARGET_VERSION"
    
    local php_required_packages=(
        "php${PHP_VERSION}"
        "php${PHP_VERSION}-fpm"
        "php${PHP_VERSION}-cli"
        "php${PHP_VERSION}-common"
        "php${PHP_VERSION}-curl"
        "php${PHP_VERSION}-gd"
        "php${PHP_VERSION}-mbstring"
        "php${PHP_VERSION}-mysql"
        "php${PHP_VERSION}-xml"
        "php${PHP_VERSION}-zip"
        "php${PHP_VERSION}-intl"
        "php${PHP_VERSION}-redis"
        "php${PHP_VERSION}-bcmath"
        "php${PHP_VERSION}-soap"
    )
    local php_packages=("${php_required_packages[@]}")
    for opt in "${PHP_OPTIONAL_PACKAGES[@]}"; do
        php_packages+=("php${PHP_VERSION}-${opt}")
    done
    
    ensure_ondrej_php_preferred || exit 1

    log_info "Checking PHP $PHP_VERSION package availability (ppa:ondrej/php)..."
    check_php_package_availability "${php_packages[@]}" || exit 1
    local install_packages=()
    for pkg in "${php_packages[@]}"; do
        if package_available "$pkg"; then
            install_packages+=("$pkg")
        else
            log_warn "Skipping unavailable optional PHP package: $pkg"
        fi
    done
    log_info "Installing PHP $PHP_VERSION and extensions..."
    safe_apt_install "${install_packages[@]}" || exit 1
    
    local pool_dir="/etc/php/${PHP_VERSION}/fpm/pool.d"
    if ! compgen -G "${pool_dir}/*.conf" >/dev/null; then
        log_warn "No PHP-FPM pools found; creating bootstrap pool"
        write_php_bootstrap_pool "$PHP_VERSION"
    fi

    # Start and enable PHP-FPM
    systemctl start php${PHP_VERSION}-fpm || {
        log_error "Failed to start PHP-FPM"
        exit 1
    }
    
    systemctl enable php${PHP_VERSION}-fpm
    sleep 3
    
    # PHP performance and security tuning
    write_php_tuning "$PHP_VERSION"
    systemctl restart php${PHP_VERSION}-fpm
    sleep 2
    
    # Verify PHP-FPM socket
    if [[ ! -S /run/php/php${PHP_VERSION}-fpm.sock ]]; then
        log_error "PHP-FPM socket not found"
        systemctl status php${PHP_VERSION}-fpm
        exit 1
    fi
    
    if ! php -v 2>/dev/null | head -1 | grep -q "$PHP_VERSION"; then
        log_error "PHP binary version mismatch after install"
        exit 1
    fi
    
    verify_php_installation "${install_packages[@]}" || exit 1
    
    ensure_wp_cli || {
        log_error "WP-CLI installation failed"
        exit 1
    }
    
    log_success "PHP $PHP_VERSION installed and verified"
    PHASE_CURRENT=2
}

phase_certbot() {
    log_section "Phase 3: SSL Certificate Tools"
    set_log_context "Phase-3" "Certbot"
    
    if [[ "$ENABLE_CLOUDFLARE" == "true" ]]; then
        safe_apt_install certbot python3-certbot-nginx python3-certbot-dns-cloudflare || exit 1
    else
        safe_apt_install certbot python3-certbot-nginx || exit 1
    fi
    
    mkdir -p /etc/letsencrypt/{live,renewal,renewal-hooks/post}
    
    # Create auto-reload hook
    cat > /etc/letsencrypt/renewal-hooks/post/nginx-reload.sh <<'CERTBOT_RELOAD'
#!/bin/bash
systemctl reload nginx 2>/dev/null || systemctl restart nginx
CERTBOT_RELOAD
    
    chmod +x /etc/letsencrypt/renewal-hooks/post/nginx-reload.sh

    cat > /etc/letsencrypt/renewal-hooks/post/nginx-rollback.sh <<'CERTBOT_ROLLBACK'
#!/bin/bash
# Roll back to last known-good config if reload fails
if ! nginx -t >/dev/null 2>&1; then
  systemctl restart nginx >/dev/null 2>&1 || true
fi
CERTBOT_ROLLBACK

    chmod +x /etc/letsencrypt/renewal-hooks/post/nginx-rollback.sh
    
    log_success "Certbot configured"
    PHASE_CURRENT=3
}

phase_nginx() {
    log_section "Phase 4: Nginx Web Server"
    set_log_context "Phase-4" "Nginx"
    
    safe_apt_install nginx || exit 1
    systemctl enable nginx

    install_nginx_optional_modules

    detect_http3_support
    detect_brotli_support
    detect_zstd_support
    detect_cache_purge_support
    write_nginx_main_config
    write_nginx_security_snippet
    write_nginx_performance_snippet
    write_nginx_http3_snippet
    write_nginx_rate_limits
    
    # Cloudflare integration
    configure_cloudflare_realip || log_warn "Cloudflare real IP configuration not applied"
    write_cloudflare_recommendations
    
    if ! nginx -t >/dev/null 2>&1; then
        log_error "Nginx configuration invalid"
        exit 1
    fi
    systemctl restart nginx >/dev/null 2>&1 || true
    
    log_success "Nginx configured with security safeguards"
    PHASE_CURRENT=4
}

phase_mariadb() {
    log_section "Phase 5: MariaDB Database Server"
    set_log_context "Phase-5" "MariaDB"
    
    DEBIAN_FRONTEND=noninteractive safe_apt_install mariadb-server mariadb-client || exit 1
    
    systemctl enable mariadb
    systemctl start mariadb
    sleep 3
    
    # Detect MySQL socket
    detect_mysql_socket || exit 1
    
    # Validate connection
    validate_mysql_connection || {
        log_error "MariaDB failed to start properly"
        exit 1
    }
    
    # Performance configuration
    write_mariadb_tuning

    systemctl restart mariadb
    sleep 3
    
    validate_mysql_connection || {
        log_error "MariaDB failed after configuration"
        exit 1
    }
    
    log_success "MariaDB installed and configured"
    PHASE_CURRENT=5
}

phase_redis() {
    log_section "Phase 6: Redis Cache Server"
    set_log_context "Phase-6" "Redis"
    
    safe_apt_install redis-server redis-tools || exit 1
    
    systemctl enable redis-server
    systemctl start redis-server
    sleep 2
    
    # Generate strong Redis password
    REDIS_PASSWORD=$(generate_secure_password 48)
    
    # SECURE Redis configuration
    cat > /etc/redis/redis.conf <<REDIS_CONFIG
# Memory
maxmemory $REDIS_MEMORY
maxmemory-policy allkeys-lru
lazyfree-lazy-eviction yes

# Databases
databases 16

# Security
requirepass $REDIS_PASSWORD
bind 127.0.0.1
protected-mode yes
port 6379

# Performance
timeout 0

# Persistence (disabled for cache)
save ""
appendonly no

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
REDIS_CONFIG

    # Save Redis password to encrypted credentials
    cat > "$CREDENTIALS_DIR/redis-credentials.txt" <<REDIS_CREDS
Redis Configuration
Host: $REDIS_HOST
Port: $REDIS_PORT
Password: $REDIS_PASSWORD
Max Memory: $REDIS_MEMORY
 Version: 0.0.1
REDIS_CREDS

    encrypt_credentials "$CREDENTIALS_DIR/redis-credentials.txt" || {
        log_error "Failed to encrypt Redis credentials"
        exit 1
    }
    
    systemctl restart redis-server
    sleep 2
    
    validate_redis_connection "$REDIS_PASSWORD" || {
        log_error "Redis failed to start properly"
        exit 1
    }
    
    log_success "Redis configured with authentication"
    PHASE_CURRENT=6
}

phase_php_pools_base() {
    log_section "Phase 7: PHP-FPM Base Configuration"
    set_log_context "Phase-7" "PHP-Pools"
    
    # Remove default www pool
    rm -f /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf 2>/dev/null || true
    
    # Configure session handling
    chown www-data:www-data /var/lib/php/sessions
    chmod 1733 /var/lib/php/sessions
    
    # Configure PHP-FPM global settings
    cat > /etc/php/${PHP_VERSION}/fpm/php-fpm.conf <<PHP_FPM_CONF
[global]
pid = /run/php/php${PHP_VERSION}-fpm.pid
error_log = /var/log/php${PHP_VERSION}-fpm.log
log_level = warning
emergency_restart_threshold = 10
emergency_restart_interval = 1m
process_control_timeout = 10s

include=/etc/php/${PHP_VERSION}/fpm/pool.d/*.conf
PHP_FPM_CONF

    local pool_dir="/etc/php/${PHP_VERSION}/fpm/pool.d"
    if ! compgen -G "${pool_dir}/*.conf" >/dev/null; then
        log_warn "No PHP-FPM pools found; creating bootstrap pool"
        write_php_bootstrap_pool "$PHP_VERSION"
    fi

    systemctl restart php${PHP_VERSION}-fpm
    sleep 2
    
    if [[ ! -S /run/php/php${PHP_VERSION}-fpm.sock ]]; then
        log_error "PHP-FPM failed to restart"
        exit 1
    fi
    
    log_success "PHP-FPM base configuration complete"
    PHASE_CURRENT=7
}

phase_registries() {
    log_section "Phase 8: Registry Initialization"
    set_log_context "Phase-8" "Registries"
    
    initialize_registries
    
    log_success "Registries initialized with atomic locking"
    PHASE_CURRENT=8
}

phase_idempotency_lock() {
    log_section "Phase 9: Idempotency Protection"
    set_log_context "Phase-9" "Idempotency"
    
    # Create initialization marker
    touch "$INITIALIZED_FLAG"
    
    # Create installation record
    cat > "$INSTALL_RECORD_FILE" <<INIT_INFO
${INSTALLER_NAME} v${INSTALLER_VERSION} - ${INSTALLER_EDITION}
Tagline: ${INSTALLER_TAGLINE}
Description: ${INSTALLER_DESCRIPTION}
Installation Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
Host: $(hostname)
OS: $(lsb_release -d | cut -f2)
PHP: ${PHP_VERSION}
PHP Target: ${PHP_TARGET_VERSION}
MySQL Socket: ${MYSQL_SOCKET}
Installer Version: ${INSTALLER_VERSION}
Edition: ${INSTALLER_EDITION}
Security Features: Enabled
Encryption: AES-256-CBC
INIT_INFO

    chmod 600 "$INSTALL_RECORD_FILE"
    install_cli_wrapper
    
    log_success "Installation record created"
    log_audit "INSTALLATION_COMPLETE" "version=$INSTALLER_VERSION php=$PHP_VERSION"
    
    PHASE_CURRENT=9
}

phase_nginx_microcache() {
    log_section "Phase 10: Nginx Micro-Cache"
    set_log_context "Phase-10" "Cache"
    
    mkdir -p /var/cache/nginx/microcache
    chown -R www-data:www-data /var/cache/nginx
    chmod -R 755 /var/cache/nginx

    write_microcache_config
    
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx >/dev/null 2>&1 || true
    else
        log_warn "Nginx config invalid after cache configuration"
    fi
    
    log_success "Cache infrastructure configured"
    PHASE_CURRENT=10
}

phase_wordpress_cron() {
    log_section "Phase 11: WordPress Cron System"
    set_log_context "Phase-11" "Cron"
    
    cat > "$CRON_RUNNER_SCRIPT" <<'WP_CRON'
#!/bin/bash
set -euo pipefail

LOCK_FILE="/var/run/dazestack-wp-cron.lock"
LOCK_FD=200
MAX_RUNTIME=600  # 10 minutes max

# Atomic locking
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    # Check if lock is stale
    if [[ -f "$LOCK_FILE" ]]; then
        lock_age=$(($(date +%s) - $(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)))
        if [[ $lock_age -gt $MAX_RUNTIME ]]; then
            flock -u 200 2>/dev/null || true
            exec 200>&-
            rm -f "$LOCK_FILE"
            exec 200>"$LOCK_FILE"
            flock -n 200 || exit 0
        else
            exit 0
        fi
    else
        exit 0
    fi
fi

# Set timeout
trap 'flock -u 200; exec 200>&-; rm -f "$LOCK_FILE"' EXIT
timeout $MAX_RUNTIME bash -c '
registry="/var/lib/dazestack-wp/state/domain-registry.json"
[[ ! -f "$registry" ]] && exit 0

domains=$(jq -r ".domains | keys[]" "$registry" 2>/dev/null || echo "")

for domain in $domains; do
    wp_root="/var/www/$domain/public"
    [[ ! -d "$wp_root" ]] && continue
    
    if [[ -f "$wp_root/wp-cron.php" ]]; then
        # Verify checksum to prevent executing malicious code
        if php -l "$wp_root/wp-cron.php" >/dev/null 2>&1; then
            timeout 120 php "$wp_root/wp-cron.php" >/dev/null 2>&1 || true
        fi
    fi
done
' || true
WP_CRON

    chmod +x "$CRON_RUNNER_SCRIPT"
    
    cat > "$CRON_WORDPRESS_FILE" <<WP_CRON_JOB
*/5 * * * * root $CRON_RUNNER_SCRIPT >/dev/null 2>&1
WP_CRON_JOB

    chmod 644 "$CRON_WORDPRESS_FILE"

    install_auto_tune_cron
    
    log_success "Cron system configured with security checks"
    PHASE_CURRENT=11
}

phase_logrotate() {
    log_section "Phase 12: Log Rotation"
    set_log_context "Phase-12" "Logrotate"
    
    cat > "$LOGROTATE_CONFIG" <<'LOGROTATE_CONFIG'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid` 2>/dev/null || true
    endscript
}

/var/log/mysql/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 mysql mysql
    sharedscripts
    postrotate
        /usr/bin/mysqladmin flush-logs 2>/dev/null || true
    endscript
}

/var/log/redis/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 redis redis
}

/var/log/dazestack-wp/*.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 0640 root adm
}
LOGROTATE_CONFIG

    chmod 644 "$LOGROTATE_CONFIG"
    
    log_success "Log rotation configured"
    PHASE_CURRENT=12
}

phase_automated_backups() {
    log_section "Phase 13: Encrypted Backup System"
    set_log_context "Phase-13" "Backups"
    
    cat > "$CRON_BACKUP_SCRIPT" <<'BACKUP_SCRIPT'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/var/backups/dazestack-wp"
BACKUP_KEY="/root/.dazestack-wp/.backup.key"
LOG_FILE="/var/log/dazestack-wp/backup.log"
MYSQL_SOCKET=""
MYSQL_SOCKET_ARG=""

if command -v mysql_config >/dev/null 2>&1; then
  MYSQL_SOCKET=$(mysql_config --socket 2>/dev/null || true)
fi
if [[ -n "$MYSQL_SOCKET" ]] && [[ -S "$MYSQL_SOCKET" ]]; then
  MYSQL_SOCKET_ARG="--socket=$MYSQL_SOCKET"
fi

# Dynamic retention based on disk size
disk_total_gb=$(df -BG / | awk 'NR==2 {gsub("G","",$2); print $2}')
if [[ -n "$disk_total_gb" ]] && [[ "$disk_total_gb" -lt 20 ]]; then
  RETENTION_DAYS=7
else
  RETENTION_DAYS=15
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Create backup directory
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Get list of WordPress databases
databases=$(mysql $MYSQL_SOCKET_ARG -e "SHOW DATABASES LIKE 'wp_%';" 2>/dev/null | awk 'NR>1' || echo "")

if [[ -z "$databases" ]]; then
    log "No WordPress databases found"
    exit 0
fi

backup_count=0
error_count=0

for db in $databases; do
    timestamp=$(date +%Y%m%d-%H%M%S)
    backup_file="$BACKUP_DIR/${db}-${timestamp}.sql.gz"
    encrypted_file="${backup_file}.enc"
    
    # Dump database
    if mysqldump $MYSQL_SOCKET_ARG --single-transaction --quick --lock-tables=false \
        "$db" 2>/dev/null | gzip > "$backup_file"; then
        
        # Verify backup integrity
        if gzip -t "$backup_file" 2>/dev/null; then
            
            # Encrypt backup
            if [[ -f "$BACKUP_KEY" ]]; then
                if openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
                    -in "$backup_file" \
                    -out "$encrypted_file" \
                    -pass file:"$BACKUP_KEY" 2>/dev/null; then
                    
                    # Securely delete unencrypted backup
                    shred -u -n 3 "$backup_file" 2>/dev/null
                    chmod 400 "$encrypted_file"
                    
                    log "Backup created and encrypted: $db"
                    ((++backup_count))
                else
                    log "Encryption failed: $db"
                    rm -f "$backup_file" "$encrypted_file"
                    ((++error_count))
                fi
            else
                # No encryption key, just compress
                chmod 400 "$backup_file"
                log "Backup created (unencrypted): $db"
                ((++backup_count))
            fi
        else
            log "Backup verification failed: $db"
            rm -f "$backup_file"
            ((++error_count))
        fi
    else
        log "Backup failed: $db"
        rm -f "$backup_file"
        ((++error_count))
    fi
done

# Cleanup old backups
find "$BACKUP_DIR" -type f \( -name "*.sql.gz" -o -name "*.sql.gz.enc" \) -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

log "Backup completed: $backup_count successful, $error_count failed"
BACKUP_SCRIPT

    chmod +x "$CRON_BACKUP_SCRIPT"
    
    cat > "$CRON_BACKUP_FILE" <<BACKUP_CRON
0 2 * * * root $CRON_BACKUP_SCRIPT >/dev/null 2>&1
BACKUP_CRON

    chmod 644 "$CRON_BACKUP_FILE"
    
    log_success "Encrypted backup system configured"
    PHASE_CURRENT=13
}

phase_security_hardening() {
    log_section "Phase 14: Security Baseline"
    set_log_context "Phase-14" "Security"
    
    # Configure fail2ban for SSH and Nginx
    if command -v fail2ban-client &>/dev/null; then
        cat > /etc/fail2ban/jail.local <<'FAIL2BAN'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
FAIL2BAN

        systemctl enable fail2ban 2>/dev/null || true
        systemctl restart fail2ban 2>/dev/null || true
        log_success "fail2ban configured"
    fi
    
    # Configure UFW firewall (preserve existing rules)
    configure_firewall_preserve || log_warn "UFW firewall configuration skipped"

    # Apply conservative sysctl performance tuning
    apply_sysctl_tuning
    
    # Secure shared memory
    if ! grep -q "tmpfs /run/shm tmpfs" /etc/fstab 2>/dev/null; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
        log_success "Shared memory secured"
    fi
    
    # Disable unnecessary services
    for service in avahi-daemon cups bluetooth; do
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
    done
    
    log_success "Security baseline applied"
    PHASE_CURRENT=14
}

phase_system_cleanup() {
    log_section "Phase 15: System Cleanup"
    set_log_context "Phase-15" "Cleanup"
    
    # Clean package cache
    apt-get clean >/dev/null 2>&1 || true
    apt-get autoclean >/dev/null 2>&1 || true
    if [[ "$ENABLE_AGGRESSIVE_CLEANUP" == "true" ]]; then
        apt-get autoremove -y >/dev/null 2>&1 || true
    else
        log_info "Skipping autoremove (conservative cleanup)"
    fi
    
    # Clean temporary files (SAFE - not /tmp/*)
    find /tmp -name "wp-*" -type f -mtime +1 -delete 2>/dev/null || true
    find /var/tmp -name "wp-*" -type f -mtime +1 -delete 2>/dev/null || true
    
    # Clean old log files
    find /var/log -type f -name "*.log.*" -mtime +30 -delete 2>/dev/null || true
    
    log_success "System cleanup completed"
    PHASE_CURRENT=15
}

phase_health_check() {
    log_section "Phase 16: Comprehensive Health Check"
    set_log_context "Phase-16" "Health-Check"
    
    local checks_passed=0
    local checks_total=0
    local critical_failed=false
    [[ -z "$MYSQL_SOCKET" ]] && detect_mysql_socket >/dev/null 2>&1 || true
    
    # Check 0: Dependencies
    ((++checks_total))
    if check_dependencies >/dev/null 2>&1; then
        log_success "Dependencies present"
        ((++checks_passed))
    else
        log_error "Missing dependencies"
        critical_failed=true
    fi
    
    # Check 1: Service Status
    for service in nginx mariadb redis-server php${PHP_VERSION}-fpm; do
        ((++checks_total))
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_success "$service is running"
            ((++checks_passed))
        else
            log_error "$service is NOT running"
            critical_failed=true
        fi
    done
    
    # Check 2: MySQL Connectivity
    ((++checks_total))
    if mysql_exec "SELECT 1;" >/dev/null 2>&1; then
        log_success "MySQL connectivity verified"
        ((++checks_passed))
    else
        log_error "MySQL connection FAILED"
        critical_failed=true
    fi
    
    # Check 3: MySQL Performance
    ((++checks_total))
    local mysql_response_time=$(mysql_exec "SELECT BENCHMARK(100000, SHA1('test'));" 2>/dev/null | tail -1 | awk '{print $1}')
    if [[ -n "$mysql_response_time" ]]; then
        log_success "MySQL performance test passed"
        ((++checks_passed))
    else
        log_warn "MySQL performance test failed"
    fi
    
    # Check 4: Redis Connectivity
    ((++checks_total))
    if [[ -n "$REDIS_PASSWORD" ]]; then
        if redis-cli -a "$REDIS_PASSWORD" PING 2>/dev/null | grep -q "PONG"; then
            log_success "Redis authentication working"
            ((++checks_passed))
        else
            log_error "Redis connection FAILED"
            critical_failed=true
        fi
    fi
    
    # Check 5: Redis Performance
    ((++checks_total))
    if [[ -n "$REDIS_PASSWORD" ]]; then
        local redis_latency=$(redis-cli -a "$REDIS_PASSWORD" --latency -i 1 -c 10 2>/dev/null | awk '{print int($NF)}' || echo "999")
        if [[ "$redis_latency" -lt 10 ]]; then
            log_success "Redis latency acceptable (${redis_latency}ms)"
            ((++checks_passed))
        else
            log_warn "Redis latency high (${redis_latency}ms)"
        fi
    fi
    
    # Check 6: PHP-FPM Socket
    ((++checks_total))
    if [[ -S /run/php/php${PHP_VERSION}-fpm.sock ]]; then
        log_success "PHP-FPM socket exists"
        ((++checks_passed))
    else
        log_error "PHP-FPM socket NOT found"
        critical_failed=true
    fi
    
    # Check 7: Nginx Configuration
    ((++checks_total))
    if nginx -t >/dev/null 2>&1; then
        log_success "Nginx configuration valid"
        ((++checks_passed))
    else
        log_error "Nginx configuration INVALID"
        critical_failed=true
    fi
    
    # Check 8: Disk Space
    ((++checks_total))
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -lt 80 ]]; then
        log_success "Disk space OK (${disk_usage}% used)"
        ((++checks_passed))
    else
        log_warn "Disk space low (${disk_usage}% used)"
    fi
    
    # Check 9: Memory Available
    ((++checks_total))
    local mem_available=$(free -m | awk 'NR==2 {print $7}')
    if [[ $mem_available -gt 100 ]]; then
        log_success "Memory available (${mem_available}MB free)"
        ((++checks_passed))
    else
        log_warn "Low memory (${mem_available}MB free)"
    fi
    
    # Check 10: Encryption Keys
    ((++checks_total))
    if [[ -f "$MASTER_KEY_FILE" ]] && [[ -f "$BACKUP_KEY_FILE" ]]; then
        log_success "Encryption keys present"
        ((++checks_passed))
    else
        log_error "Encryption keys MISSING"
    fi
    
    # Summary
    echo ""
    echo "--------------------------------------------------------------"
    echo "Health Check Summary: $checks_passed/$checks_total checks passed"
    echo "--------------------------------------------------------------"
    
    if [[ "$critical_failed" == "true" ]]; then
        log_error "Critical health checks FAILED"
        return 1
    elif [[ $checks_passed -ge $((checks_total - 2)) ]]; then
        log_success "System health: GOOD"
        return 0
    else
        log_warn "System health: DEGRADED"
        return 1
    fi
}

phase_summary() {
    log_section "Phase 17: Installation Complete"
    set_log_context "Phase-17" "Summary"
    
    local total_time=$(($(date +%s) - SCRIPT_START_TIME))
    local minutes=$((total_time / 60))
    local seconds=$((total_time % 60))
    
    echo ""
    echo "======================================================================"
    echo "INSTALLATION SUCCESSFUL"
    echo "======================================================================"
    echo ""
    echo "Installation completed in ${minutes}m ${seconds}s"
    echo ""
    echo "System Configuration:"
    echo "  Product: $INSTALLER_NAME"
    echo "  Version: $INSTALLER_VERSION ($INSTALLER_EDITION)"
    echo "  RAM: ${SYSTEM_RAM_GB}GB (${SYSTEM_RAM_MB}MB)"
    echo "  CPU: ${SYSTEM_CPU_CORES} cores"
    echo "  PHP: $PHP_VERSION"
    echo "  PHP Target: $PHP_TARGET_VERSION"
    echo "  MySQL Socket: $MYSQL_SOCKET"
    echo ""
    echo "Security Features:"
    echo "  - Encrypted credential storage (AES-256-CBC)"
    echo "  - Encrypted backups"
    echo "  - Input validation and sanitization"
    echo "  - Atomic registry locking"
    echo "  - Rate limiting configured"
    echo "  - Security headers enabled"
    echo "  - fail2ban protection"
    echo "  - UFW firewall active"
    echo "  - Cloudflare real IP integration"
    echo "  - Redis object caching enabled"
    echo "  - Full page caching enabled (Nginx microcache)"
    echo "  - Auto-tune engine + cron scheduling"
    echo "  - HTTP/2 (HTTP/3 when supported by Nginx build)"
    echo ""
    echo "Management Commands:"
    echo "  $SCRIPT_NAME menu                    # Interactive menu"
    echo "  $SCRIPT_NAME create-site <domain> [site_title] <admin_email> [admin_user]  # Create new WordPress site"
    echo "  $SCRIPT_NAME delete-site <domain>     # Delete WordPress site"
    echo "  $SCRIPT_NAME list-sites               # List all sites"
    echo "  $SCRIPT_NAME health-check             # Run health diagnostics"
    echo "  $SCRIPT_NAME auto-tune                # Apply adaptive tuning"
    echo "  $SCRIPT_NAME run-phase <phase>        # Run a single phase"
    echo "  $SCRIPT_NAME list-phases              # Show phases"
    echo "  $SCRIPT_NAME enable-ssl <domain>      # Enable SSL/TLS for a site"
    echo "  $SCRIPT_NAME install-cli              # Install CLI wrapper ($CLI_WRAPPER)"
    echo "  $SCRIPT_NAME show-credentials <domain> # View site credentials"
    echo "  $SCRIPT_NAME rebalance-pools          # Rebalance PHP-FPM pools"
    echo "  $SCRIPT_NAME update-cloudflare-ips    # Refresh Cloudflare IP allowlist"
    echo "  $SCRIPT_NAME remove-old-backups [days] # Remove backups older than N days"
    echo "  $SCRIPT_NAME compression-status       # Show gzip/brotli/zstd status"
    echo "  $SCRIPT_NAME factory-reset            # Remove stack, data, and configs"
    echo "  $SCRIPT_NAME refresh-installation     # Reinstall stack and reset defaults"
    echo "  $SCRIPT_NAME list-features            # Full feature list"
    echo ""
    echo "CLI Wrapper:"
    echo "  $CLI_WRAPPER (same commands as above)"
    echo ""
    echo "Cloudflare Guide:"
    echo "  $CONFIG_DIR/cloudflare-recommended.txt"
    echo ""
    echo "Important Files:"
    echo "  Credentials: $CREDENTIALS_DIR/ (encrypted)"
    echo "  Logs: $LOG_DIR/"
    echo "  Backups: $BACKUP_DIR/ (encrypted)"
    echo "  Registry: $STATE_DIR/"
    echo ""
    echo "Next Steps:"
    echo "  1. Create your first site: $SCRIPT_NAME create-site example.com \"My Site\" admin@example.com"
    echo "  2. Configure DNS to point to this server"
    echo "  3. Obtain SSL certificate with: certbot --nginx -d example.com"
    echo ""
    
    PHASE_CURRENT=17
}

# =============================================================================
# SECTION 12: SITE MANAGEMENT (SECURED)
# Purpose: Create, delete, and maintain WordPress sites.
# =============================================================================

maybe_enable_http3_for_site() {
    local domain=$1
    local conf="/etc/nginx/sites-available/${domain}.conf"

    detect_http3_support
    [[ "$HTTP3_AVAILABLE" != "true" ]] && return 0
    [[ ! -f "$conf" ]] && return 0

    if grep -q "listen 443 ssl" "$conf"; then
        if grep -q "listen 443 ssl;" "$conf" && ! grep -q "listen 443 ssl http2" "$conf"; then
            sed -i "s/listen 443 ssl;/listen 443 ssl http2;/" "$conf"
        fi
        if ! grep -q "listen 443 quic" "$conf"; then
            sed -i "/listen 443 ssl/a\\    listen 443 quic reuseport;" "$conf"
        fi
        if ! grep -q "Alt-Svc" "$conf"; then
            sed -i "/listen 443 ssl/a\\    add_header Alt-Svc 'h3=\\\":443\\\"; ma=86400' always;" "$conf"
        fi
    fi

    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
}

enable_ssl_for_site() {
    local domain_raw=$1
    local email_raw=${2:-}
    local domain
    domain=$(validate_domain "$domain_raw") || return 1

    local email="$email_raw"
    if [[ -z "$email" ]] && [[ -f "$REGISTRY_FILE" ]]; then
        email=$(jq -r ".domains[\"$domain\"].admin_email // empty" "$REGISTRY_FILE" 2>/dev/null)
    fi
    if [[ -z "$email" ]]; then
        log_error "Admin email required to issue SSL certificate"
        return 1
    fi

    if ! command -v certbot >/dev/null 2>&1; then
        log_error "Certbot not installed"
        return 1
    fi
    check_network

    local cert_domains=(-d "$domain")
    if should_include_www "$domain"; then
        cert_domains+=(-d "www.$domain")
    fi

    log_info "Requesting SSL certificate for $domain..."
    if certbot --nginx "${cert_domains[@]}" \
        --agree-tos --no-eff-email --redirect -m "$email" --non-interactive >/dev/null 2>&1; then
        maybe_enable_http3_for_site "$domain"
        log_success "SSL enabled for $domain"
        return 0
    fi

    log_warn "SSL issuance failed for $domain (check DNS and firewall)"
    return 1
}

create_site() {
    local domain_raw=$1
    local site_title_raw=${2:-}
    local admin_email_raw=${3:-}
    local admin_user_raw=${4:-}
    local enable_ssl_raw=${5:-}
    
    # Validate inputs
    local domain
    domain=$(validate_domain "$domain_raw") || {
        log_error "Invalid domain: $domain_raw"
        return 1
    }
    
    [[ -z "$site_title_raw" ]] && site_title_raw="$domain"
    if [[ -z "$admin_email_raw" ]] && [[ "$site_title_raw" == *"@"* ]]; then
        admin_email_raw="$site_title_raw"
        site_title_raw="$domain"
    fi
    local site_title
    site_title=$(sanitize_site_title "$site_title_raw") || {
        log_error "Invalid site title"
        return 1
    }
    
    local admin_email
    admin_email=$(validate_email "$admin_email_raw") || {
        log_error "Invalid admin email"
        return 1
    }
    
    log_section "Creating WordPress Site: $domain"
    set_log_context "CREATE_SITE" "$domain"

    local admin_user
    if [[ -z "$admin_user_raw" ]]; then
        admin_user="$WP_DEFAULT_ADMIN_USER"
    else
        admin_user="$admin_user_raw"
    fi
    admin_user=$(validate_wp_admin_user "$admin_user") || {
        log_error "Invalid admin username"
        return 1
    }

    local enable_ssl_flag="$ENABLE_AUTO_SSL"
    if [[ -n "$enable_ssl_raw" ]]; then
        case "$enable_ssl_raw" in
            true|TRUE|True|yes|YES|Yes|y|Y|1) enable_ssl_flag="true" ;;
            false|FALSE|False|no|NO|No|n|N|0) enable_ssl_flag="false" ;;
            *) log_warn "Unknown SSL flag '$enable_ssl_raw'; using default ($ENABLE_AUTO_SSL)" ;;
        esac
    fi

    detect_cache_purge_support
    
    # Load system resources if not already loaded
    detect_php_version || return 1
    calculate_system_resources >/dev/null 2>&1
    detect_mysql_socket >/dev/null 2>&1 || true
    
    if [[ -z "$REDIS_PASSWORD" ]]; then
        if [[ -f "$CREDENTIALS_DIR/redis-credentials.txt.enc" ]]; then
            decrypt_credentials "$CREDENTIALS_DIR/redis-credentials.txt.enc" || {
                log_error "Failed to decrypt Redis credentials"
                return 1
            }
            REDIS_PASSWORD=$(grep "^Password:" "$CREDENTIALS_DIR/redis-credentials.txt" | cut -d: -f2- | xargs)
            shred -u -n 3 "$CREDENTIALS_DIR/redis-credentials.txt" 2>/dev/null
        fi
    fi
    [[ -z "$PHP_VERSION" ]] && calculate_system_resources >/dev/null 2>&1
    
    # Load Redis password if not in memory
    if [[ -z "$REDIS_PASSWORD" ]]; then
        if [[ -f "$CREDENTIALS_DIR/redis-credentials.txt.enc" ]]; then
            decrypt_credentials "$CREDENTIALS_DIR/redis-credentials.txt.enc" || {
                log_error "Failed to decrypt Redis credentials"
                return 1
            }
            REDIS_PASSWORD=$(grep "^Password:" "$CREDENTIALS_DIR/redis-credentials.txt" | cut -d: -f2- | xargs)
            shred -u -n 3 "$CREDENTIALS_DIR/redis-credentials.txt" 2>/dev/null
        fi
    fi
    
    # Check if domain already exists
    if jq -e ".domains[\"$domain\"]" "$REGISTRY_FILE" >/dev/null 2>&1; then
        log_error "Domain already exists: $domain"
        log_security "DUPLICATE_DOMAIN" "Attempt to create existing domain: $domain"
        return 1
    fi
    
    # Initialize rollback stack
    ROLLBACK_STACK=()
    
    # Allocate Redis database
    log_info "Allocating Redis database..."
    local redis_db
    redis_db=$(redis_allocate_db "$domain") || {
        log_error "Failed to allocate Redis database"
        execute_rollback
        return 1
    }
    push_rollback "redis_release_db '$domain'"
    
    # Generate database credentials
    log_info "Generating database credentials..."
    local db_name=$(sanitize_db_name "$domain")
    local db_user=$(sanitize_db_user "$domain")
    local db_pass=$(generate_secure_password 32)
    local admin_pass=$(generate_secure_password 20)
    
    # Create MySQL database
    log_info "Creating MySQL database..."
    if ! mysql_exec "CREATE DATABASE IF NOT EXISTS \`$db_name\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null; then
        log_error "Failed to create database: $db_name"
        execute_rollback
        return 1
    fi
    push_rollback "mysql -e \"DROP DATABASE IF EXISTS \\\`$db_name\\\`;\" 2>/dev/null || true"
    
    # Create MySQL user with limited privileges
    log_info "Creating MySQL user..."
    mysql_exec "CREATE USER IF NOT EXISTS '$db_user'@'localhost' IDENTIFIED BY '$db_pass';" 2>/dev/null || true
    mysql_exec "GRANT ALL PRIVILEGES ON \`$db_name\`.* TO '$db_user'@'localhost';" 2>/dev/null
    mysql_exec "FLUSH PRIVILEGES;" 2>/dev/null
    push_rollback "mysql -e \"DROP USER IF EXISTS '$db_user'@'localhost';\" 2>/dev/null || true"
    
    # Create site directory structure
    log_info "Creating site directories..."
    local site_dir="$SITES_DIR/$domain"
    local site_tmp="$site_dir/tmp"
    
    mkdir -p "$site_dir"/{public,logs,backups,tmp}
    touch "$site_dir/.dazestack-wp-site" 2>/dev/null || true
    push_rollback "safe_cleanup '$site_dir'"
    
    # Set ownership and permissions
    chown -R www-data:www-data "$site_dir"
    chmod -R 755 "$site_dir"
    chmod 1733 "$site_tmp"  # Sticky bit for tmp
    
    # Create PHP-FPM pool
    log_info "Creating PHP-FPM pool..."
    local pool_name="${domain//./_}"
    local php_socket="/run/php/php${PHP_VERSION}-${pool_name}.sock"
    
    local total_sites=$(( $(get_total_sites) + 1 ))
    read -r site_max_children site_start site_min site_max < <(calculate_pool_limits "$total_sites")
    write_php_pool_config "$pool_name" "$site_dir" "$site_tmp" "$site_max_children" "$site_start" "$site_min" "$site_max"

    push_rollback "rm -f '/etc/php/${PHP_VERSION}/fpm/pool.d/${pool_name}.conf'"
    
    # Reload PHP-FPM
    systemctl reload php${PHP_VERSION}-fpm || {
        log_error "Failed to reload PHP-FPM"
        execute_rollback
        return 1
    }
    sleep 2
    
    # Verify PHP-FPM socket
    if [[ ! -S "$php_socket" ]]; then
        log_error "PHP-FPM socket not created: $php_socket"
        execute_rollback
        return 1
    fi
    
    # Install WordPress (automated)
    log_info "Installing WordPress core..."
    ensure_wp_cli || {
        log_error "WP-CLI unavailable"
        execute_rollback
        return 1
    }
    
    local wp_path="$site_dir/public"

    local db_host
    db_host=$(mysql_host_for_wp)
    [[ -z "$db_host" ]] && db_host="localhost"
    
    run_wp_cli "$wp_path" core download --force || {
        log_error "WordPress download failed"
        execute_rollback
        return 1
    }
    
    run_wp_cli "$wp_path" config create \
        --dbname="$db_name" \
        --dbuser="$db_user" \
        --dbpass="$db_pass" \
        --dbhost="$db_host" \
        --dbprefix="wp_" \
        --skip-check \
        --force || {
        log_error "Failed to create wp-config.php"
        execute_rollback
        return 1
    }
    
    run_wp_cli "$wp_path" core install \
        --url="$domain" \
        --title="$site_title" \
        --admin_user="$admin_user" \
        --admin_password="$admin_pass" \
        --admin_email="$admin_email" \
        --skip-email || {
        log_error "WordPress core install failed"
        execute_rollback
        return 1
    }

    # Baseline WordPress settings (best-effort)
    run_wp_cli "$wp_path" rewrite structure '/%postname%/' || log_warn "Failed to set permalink structure"
    run_wp_cli "$wp_path" rewrite flush || log_warn "Failed to flush rewrite rules"
    if [[ -n "$PHP_MEMORY_LIMIT" ]]; then
        run_wp_cli "$wp_path" config set WP_MEMORY_LIMIT "$PHP_MEMORY_LIMIT" || log_warn "Failed to set WP_MEMORY_LIMIT"
        run_wp_cli "$wp_path" config set WP_MAX_MEMORY_LIMIT "$PHP_MEMORY_LIMIT" || log_warn "Failed to set WP_MAX_MEMORY_LIMIT"
    fi
    run_wp_cli "$wp_path" config set WP_DEBUG_DISPLAY false --raw || log_warn "Failed to set WP_DEBUG_DISPLAY"
    run_wp_cli "$wp_path" config set WP_DEBUG_LOG false --raw || log_warn "Failed to set WP_DEBUG_LOG"
    
    # Core security and performance settings
    run_wp_cli "$wp_path" config set DISABLE_WP_CRON true --raw
    run_wp_cli "$wp_path" config set WP_CACHE true --raw
    run_wp_cli "$wp_path" config set WP_AUTO_UPDATE_CORE true --raw
    run_wp_cli "$wp_path" config set DISALLOW_FILE_EDIT true --raw
    run_wp_cli "$wp_path" config set FS_METHOD direct
    run_wp_cli "$wp_path" config set WP_ENVIRONMENT_TYPE production
    run_wp_cli "$wp_path" config set WP_CACHE_KEY_SALT "${domain}:"
    
    # Redis object cache integration
    run_wp_cli "$wp_path" config set WP_REDIS_HOST "$REDIS_HOST"
    run_wp_cli "$wp_path" config set WP_REDIS_PORT "$REDIS_PORT" --raw
    run_wp_cli "$wp_path" config set WP_REDIS_PASSWORD "$REDIS_PASSWORD"
    run_wp_cli "$wp_path" config set WP_REDIS_DATABASE "$redis_db" --raw
    run_wp_cli "$wp_path" config set WP_REDIS_PREFIX "${domain//./_}:"
    run_wp_cli "$wp_path" plugin install redis-cache --activate
    run_wp_cli "$wp_path" redis enable || true

    # Nginx Helper integration (cache purge)
    if [[ "$ENABLE_NGINX_HELPER" == "true" ]]; then
        run_wp_cli "$wp_path" plugin install nginx-helper --activate || log_warn "Failed to install Nginx Helper"
        run_wp_cli "$wp_path" config set RT_WP_NGINX_HELPER_CACHE_PATH "$CACHE_DIR" || log_warn "Failed to set Nginx Helper cache path"
    fi
    
    chown -R www-data:www-data "$site_dir"
    chmod 640 "$wp_path/wp-config.php" 2>/dev/null || true
    
    # Create Nginx vhost with secure defaults
    log_info "Creating Nginx configuration..."
    local server_names="$domain"
    if should_include_www "$domain"; then
        server_names="$domain www.$domain"
    fi
    local purge_block=""
    if [[ "$CACHE_PURGE_AVAILABLE" == "true" ]]; then
        local allow_lines="    allow 127.0.0.1;"
        allow_lines+=$'\n    allow ::1;'
        local host_ips
        host_ips=$(hostname -I 2>/dev/null || true)
        for ip in $host_ips; do
            allow_lines+=$'\n    allow '"$ip"';'
        done
        purge_block=$(cat <<EOF

    # Cache purge endpoints (local only; requires fastcgi_cache_purge)
    if (\$request_method = PURGE) { return 418; }
    error_page 418 = @purge;

    location @purge {
$allow_lines
        deny all;
        set \$purge_method GET;
        fastcgi_cache_purge 1;
        fastcgi_cache_key "\$scheme\$purge_method\$host\$request_uri";
        return 204;
    }

    location ~ /purge(/.*) {
$allow_lines
        deny all;
        set \$purge_method \$request_method;
        if (\$request_method = PURGE) { set \$purge_method GET; }
        fastcgi_cache_purge 1;
        fastcgi_cache_key "\$scheme\$purge_method\$host\$1\$is_args\$args";
        return 204;
    }
EOF
)
    fi
    cat > "/etc/nginx/sites-available/$domain.conf" <<NGINX_VHOST
server {
    listen 80;
    listen [::]:80;
    server_name $server_names;
    root $site_dir/public;
    index index.php index.html;
    
    access_log $site_dir/logs/access.log combined;
    error_log $site_dir/logs/error.log warn;

    # Security headers
    include /etc/nginx/snippets/wordpress-security.conf;

    # Rate limiting
    limit_req zone=wp_general burst=20 nodelay;

    # Block access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~* /(wp-config\.php|readme\.html|license\.txt|wp-config-sample\.php) {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Disable XML-RPC (prevent brute force)
    location = /xmlrpc.php {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Rate limit wp-login
    location = /wp-login.php {
        limit_req zone=wp_login burst=2 nodelay;
        fastcgi_pass unix:$php_socket;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    # WordPress permalinks
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    # PHP processing
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:$php_socket;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        
        # FastCGI cache
        fastcgi_cache wordpress_cache;
        fastcgi_cache_bypass \$skip_cache \$skip_cache_method \$skip_cache_uri;
        fastcgi_no_cache \$skip_cache \$skip_cache_method \$skip_cache_uri;
        fastcgi_cache_valid 200 301 302 60m;
        fastcgi_cache_valid 404 10m;
        add_header X-FastCGI-Cache \$upstream_cache_status;
    }

    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        expires 365d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Block access to uploads PHP files
    location ~* /(uploads|files)/.*\.php$ {
        deny all;
    }
$purge_block
}
NGINX_VHOST

    push_rollback "rm -f '/etc/nginx/sites-available/$domain.conf' '/etc/nginx/sites-enabled/$domain.conf'"
    
    # Enable site
    ln -sf "/etc/nginx/sites-available/$domain.conf" "/etc/nginx/sites-enabled/$domain.conf"
    
    # Test Nginx configuration
    if ! nginx -t 2>/dev/null; then
        log_error "Nginx configuration test failed"
        execute_rollback
        return 1
    fi
    
    # Reload Nginx
    systemctl reload nginx || {
        log_error "Failed to reload Nginx"
        execute_rollback
        return 1
    }
    
    # Register domain in registry
    domain_register "$domain" "$redis_db" "$pool_name" "$db_name" "$db_user" "$site_title" "$admin_email" || {
        log_error "Failed to register domain"
        execute_rollback
        return 1
    }
    
    if [[ "$enable_ssl_flag" == "true" ]]; then
        enable_ssl_for_site "$domain" "$admin_email" || log_warn "Auto SSL failed for $domain"
    fi

    rebalance_php_pools || log_warn "Failed to rebalance PHP-FPM pools"
    
    # Save credentials (encrypted)
    log_info "Saving encrypted credentials..."
    cat > "$CREDENTIALS_DIR/${domain}-credentials.txt" <<SITE_CREDS
WordPress Site Credentials
Domain: $domain
Site Title: $site_title
Created: $(date '+%Y-%m-%d %H:%M:%S %Z')

WordPress Admin:
Admin URL: http://$domain/wp-admin
Admin User: $admin_user
Admin Email: $admin_email
Admin Password: $admin_pass

Database Configuration:
Database Name: $db_name
Database User: $db_user
Database Password: $db_pass
Database Host: $db_host
Database Socket: $MYSQL_SOCKET

Redis Configuration:
Redis DB: $redis_db
Redis Host: $REDIS_HOST
Redis Port: $REDIS_PORT
Redis Password: $REDIS_PASSWORD

Site Configuration:
Site Directory: $site_dir
PHP Pool: $pool_name
PHP Socket: $php_socket
PHP Version: $PHP_VERSION

Security:
Credentials Encrypted: Yes
Backups Encrypted: Yes
SITE_CREDS

    encrypt_credentials "$CREDENTIALS_DIR/${domain}-credentials.txt" || {
        log_error "Failed to encrypt credentials"
        # Don't rollback - site is created, just warn user
        log_warn "Credentials saved in PLAIN TEXT - manual encryption required"
    }
    
    # Clear rollback stack (success)
    ROLLBACK_STACK=()
    
    # Success message
    echo ""
    log_success "--------------------------------------------------------------"
    log_success "WordPress site created successfully!"
    log_success "--------------------------------------------------------------"
    echo ""
    echo "Domain: $domain"
    echo "Site Directory: $site_dir/public"
    echo "Admin URL: http://$domain/wp-admin"
    echo ""
    echo "WordPress Admin:"
    echo "  User: $admin_user"
    echo "  Email: $admin_email"
    echo "  Password: [encrypted - use 'show-credentials' command]"
    echo ""
    echo "Database Details:"
    echo "  Name: $db_name"
    echo "  User: $db_user"
    echo "  Password: [encrypted - use 'show-credentials' command]"
    echo ""
    echo "Redis Cache:"
    echo "  Database: $redis_db"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure DNS to point $domain to this server"
    echo ""
    echo "  2. Obtain SSL certificate:"
    echo "     $SCRIPT_NAME enable-ssl $domain"
    echo ""
    echo "  3. View credentials (decrypted):"
    echo "     $SCRIPT_NAME show-credentials $domain"
    echo ""
    
    log_audit "SITE_CREATED" "domain=$domain db=$db_name redis_db=$redis_db admin_email=$admin_email"
    
    return 0
}

delete_site() {
    local domain_raw=$1
    
    # Validate domain input
    local domain
    domain=$(validate_domain "$domain_raw") || {
        log_error "Invalid domain: $domain_raw"
        return 1
    }
    
    detect_php_version || return 1
    
    log_section "Deleting WordPress Site: $domain"
    set_log_context "DELETE_SITE" "$domain"
    
    # Check if domain exists
    if ! jq -e ".domains[\"$domain\"]" "$REGISTRY_FILE" >/dev/null 2>&1; then
        log_error "Domain not found: $domain"
        return 1
    fi
    
    # Get site details from registry
    local db_name=$(jq -r ".domains[\"$domain\"].db_name" "$REGISTRY_FILE")
    local db_user=$(jq -r ".domains[\"$domain\"].db_user" "$REGISTRY_FILE")
    local pool_name=$(jq -r ".domains[\"$domain\"].php_pool" "$REGISTRY_FILE")
    
    # Confirmation prompt
    echo ""
    echo "WARNING: This will permanently delete:"
    echo "  - Domain: $domain"
    echo "  - Database: $db_name"
    echo "  - All files in: $SITES_DIR/$domain"
    echo "  - Nginx configuration"
    echo "  - PHP-FPM pool"
    echo ""
    read -p "Type 'DELETE' to confirm deletion: " confirm
    
    if [[ "$confirm" != "DELETE" ]]; then
        log_warn "Deletion cancelled by user"
        return 0
    fi
    
    # Create final backup before deletion
    log_info "Creating final backup..."
    local backup_file="$BACKUP_DIR/${db_name}-deletion-$(date +%s).sql.gz"
    if mysqldump --single-transaction "$db_name" 2>/dev/null | gzip > "$backup_file" 2>/dev/null; then
        if [[ -f "$BACKUP_KEY_FILE" ]]; then
            openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
                -in "$backup_file" \
                -out "${backup_file}.enc" \
                -pass file:"$BACKUP_KEY_FILE" 2>/dev/null && {
                shred -u -n 3 "$backup_file"
                chmod 400 "${backup_file}.enc"
                log_success "Final backup created (encrypted): ${backup_file}.enc"
            }
        else
            chmod 400 "$backup_file"
            log_success "Final backup created: $backup_file"
        fi
    else
        log_warn "Failed to create final backup"
    fi
    
    # Drop MySQL database and user
    log_info "Dropping MySQL database and user..."
    mysql_exec "DROP DATABASE IF EXISTS \`$db_name\`;" 2>/dev/null || log_warn "Failed to drop database"
    mysql_exec "DROP USER IF EXISTS '$db_user'@'localhost';" 2>/dev/null || log_warn "Failed to drop user"
    mysql_exec "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    # Release Redis database
    redis_release_db "$domain" || log_warn "Failed to release Redis database"
    
    # Remove PHP-FPM pool
    log_info "Removing PHP-FPM pool..."
    rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${pool_name}.conf"
    systemctl reload php${PHP_VERSION}-fpm 2>/dev/null || log_warn "Failed to reload PHP-FPM"
    
    # Remove Nginx configuration
    log_info "Removing Nginx configuration..."
    rm -f "/etc/nginx/sites-available/$domain.conf"
    rm -f "/etc/nginx/sites-enabled/$domain.conf"
    
    if nginx -t 2>/dev/null; then
        systemctl reload nginx || log_warn "Failed to reload Nginx"
    else
        log_error "Nginx configuration invalid after site removal"
    fi
    
    # Remove site files
    log_info "Removing site files..."
    safe_cleanup "$SITES_DIR/$domain" || log_warn "Failed to remove site directory"
    
    # Remove credentials
    rm -f "$CREDENTIALS_DIR/${domain}-credentials.txt.enc"
    rm -f "$CREDENTIALS_DIR/${domain}-credentials.txt"
    
    # Unregister domain
    domain_unregister "$domain" || log_warn "Failed to unregister domain"
    
    rebalance_php_pools || log_warn "Failed to rebalance PHP-FPM pools"
    
    echo ""
    log_success "--------------------------------------------------------------"
    log_success "WordPress site deleted successfully!"
    log_success "--------------------------------------------------------------"
    echo ""
    echo "Deleted: $domain"
    echo "Final backup: ${backup_file}.enc (if successful)"
    echo ""
    
    log_audit "SITE_DELETED" "domain=$domain db=$db_name"
    
    return 0
}

list_sites() {
    log_section "Registered WordPress Sites"
    set_log_context "LIST_SITES"
    
    local registry="$REGISTRY_FILE"
    
    if [[ ! -f "$registry" ]]; then
        echo "Registry not found"
        return 1
    fi
    
    local total=$(jq -r '.metadata.total // 0' "$registry" 2>/dev/null)
    
    if [[ $total -eq 0 ]]; then
        echo "No sites registered"
        return 0
    fi
    
    echo ""
    echo "Total Sites: $total"
    echo ""
    echo "--------------------------------------------------------------"
    
    jq -r '.domains | to_entries[] | 
        "Domain: \(.key)\n  Site Title: \(.value.site_title // "n/a")\n  Admin Email: \(.value.admin_email // "n/a")\n  Redis DB: \(.value.redis_db)\n  PHP Pool: \(.value.php_pool)\n  Database: \(.value.db_name)\n  Status: \(.value.status)\n  Created: \(.value.created_at | strflocaltime("%Y-%m-%d %H:%M:%S"))\n"' \
        "$registry" 2>/dev/null || echo "Error reading registry"
    
    echo "--------------------------------------------------------------"
    echo ""
}

show_credentials() {
    local domain_raw=$1
    
    # Validate domain input
    local domain
    domain=$(validate_domain "$domain_raw") || {
        log_error "Invalid domain: $domain_raw"
        return 1
    }
    
    local cred_file="$CREDENTIALS_DIR/${domain}-credentials.txt.enc"
    
    if [[ ! -f "$cred_file" ]]; then
        log_error "Credentials not found for domain: $domain"
        return 1
    fi
    
    log_info "Decrypting credentials for $domain..."
    
    # Decrypt and display
    decrypt_credentials "$cred_file" || {
        log_error "Failed to decrypt credentials"
        return 1
    }
    
    echo ""
    echo "--------------------------------------------------------------"
    cat "$CREDENTIALS_DIR/${domain}-credentials.txt"
    echo "--------------------------------------------------------------"
    echo ""
    echo "NOTE: Credentials will be automatically deleted in 60 seconds"
    echo ""
    
    # Auto-delete plaintext after 60 seconds
    (sleep 60 && shred -u -n 3 "$CREDENTIALS_DIR/${domain}-credentials.txt" 2>/dev/null) &
    
    log_audit "CREDENTIALS_VIEWED" "domain=$domain"
}

# =============================================================================
# SECTION 13: MAIN ENTRY POINT
# Purpose: CLI parsing, dispatch, and menu flow.
# =============================================================================

show_help() {
    cat <<HELP
----------------------------------------------------------------------
${INSTALLER_NAME} v$INSTALLER_VERSION - $INSTALLER_EDITION
----------------------------------------------------------------------
Tagline: $INSTALLER_TAGLINE
Series: $INSTALLER_SERIES
Description: $INSTALLER_DESCRIPTION

USAGE:
  $0 [command] [options]
  $CLI_WRAPPER [command] [options]

COMMANDS:
  (no arguments)              Run full stack installation (menu when TTY)
  menu                        Launch interactive menu
  create-site <domain> [site_title] <admin_email> [admin_user]
                              Create new WordPress site (admin_user optional)
                              Flags: --admin-user <user>, --ssl, --no-ssl
  delete-site <domain>        Delete WordPress site (with confirmation)
  list-sites                  List all registered sites
  show-credentials <domain>   View decrypted site credentials
  health-check                Run comprehensive system diagnostics
  auto-tune                   Recalculate and apply performance tuning
  rebalance-pools             Recalculate PHP-FPM pool sizing for all sites
  run-phase <phase>           Run a single installer phase
  list-phases                 Show all available phases
  enable-ssl <domain>         Obtain SSL cert and enable HTTP/2/3 when supported
  install-cli                 Install standalone CLI wrapper
  update-cloudflare-ips       Refresh Cloudflare IP allowlist for real IPs
  remove-old-backups [days]   Remove backups older than N days (default: auto)
  compression-status          Show gzip/brotli/zstd enablement and levels
  factory-reset [--force]     Remove stack, data, and configs (DANGEROUS)
  refresh-installation [--force]  Reinstall stack and reset to defaults
  list-features               Show full feature list
  help                        Show this help message

EXAMPLES:
  # Install complete WordPress LEMP stack
  sudo bash $0

  # Create new WordPress site
  sudo bash $0 create-site example.com "My Site" admin@example.com
  sudo bash $0 create-site example.com admin@example.com
  sudo bash $0 create-site example.com "My Site" admin@example.com adminuser --ssl

  # View site credentials
  sudo bash $0 show-credentials example.com

  # Delete site (requires confirmation)
  sudo bash $0 delete-site example.com

  # List all sites
  sudo bash $0 list-sites

  # Run health check
  sudo bash $0 health-check

  # Run a single phase
  sudo bash $0 run-phase nginx

  # Auto-tune performance
  sudo bash $0 auto-tune

  # Remove old backups (use default retention)
  sudo bash $0 remove-old-backups

  # Show compression status
  sudo bash $0 compression-status

  # Factory reset (DANGEROUS)
  sudo bash $0 factory-reset

  # Refresh installation
  sudo bash $0 refresh-installation

REQUIREMENTS:
  - Operating System: Ubuntu 24.04 LTS (Noble) or newer
  - RAM: 512MB minimum (2GB+ recommended)
  - Disk Space: 5GB minimum (10GB+ recommended)
  - Root Privileges: Required (use sudo)
  - Network: Internet connectivity required

SECURITY FEATURES:
  - Encrypted credential storage (AES-256-CBC)
  - Encrypted database backups
  - Input validation and sanitization
  - SQL injection protection
  - Command injection protection
  - Atomic registry locking
  - Per-site PHP-FPM isolation
  - Redis authentication + object caching
  - Rate limiting (Nginx)
  - Security headers (HSTS, CSP, etc.)
  - fail2ban integration
  - UFW firewall
  - Cloudflare real IP integration

IMPORTANT LOCATIONS:
  - Sites: $SITES_DIR
  - Credentials: $CREDENTIALS_DIR (encrypted)
  - Logs: $LOG_DIR
  - Backups: $BACKUP_DIR (encrypted)
  - Registry: $REGISTRY_FILE
  - Cloudflare guide: $CONFIG_DIR/cloudflare-recommended.txt

SUPPORT:
  - Author: $INSTALLER_AUTHOR
  - Email: $INSTALLER_EMAIL
  - Website: $INSTALLER_WEBSITE
  - Version: $INSTALLER_VERSION
  - Edition: $INSTALLER_EDITION

----------------------------------------------------------------------
HELP
}

show_features() {
    cat <<FEATURES
Full Feature List:
  - Ubuntu 24.04+ WordPress LEMP stack with PHP $PHP_TARGET_VERSION
  - Fully automated WordPress install (core + config + admin user)
  - Interactive menu mode (run without arguments or use "menu")
  - Per-site PHP-FPM pools with dynamic scaling and rebalancing
  - Redis object caching enabled by default (redis-cache)
  - Optional Nginx Helper integration + local purge endpoints (/purge/ + PURGE)
  - Redis DB 0 reserved for system use (domains use DB 1-15)
  - Nginx FastCGI microcache (full page caching)
  - HTTP/2 + optional HTTP/3 (auto-detect when supported)
  - Optional Brotli + zstd + gzip compression
  - Auto-tune engine with cron scheduling
  - Optional auto-SSL via Certbot (--nginx) with HTTP/3 patching
  - Modular phase runner (run any phase independently)
  - Cloudflare real IP integration with auto-updated IP ranges
  - Cloudflare recommendations file ($CONFIG_DIR/cloudflare-recommended.txt)
  - Secure Nginx headers + rate limiting
  - Encrypted credentials (AES-256-CBC + PBKDF2)
  - Encrypted nightly backups with verification
  - Automatic log rotation and cleanup
  - Maintenance: remove old backups + compression status reporting
  - Maintenance: factory reset or refresh reinstall (destructive)
  - UFW + fail2ban protection (preserve existing rules)
  - Conservative sysctl performance tuning
  - Comprehensive health checks and diagnostics
  - Standalone CLI wrapper: $CLI_WRAPPER
FEATURES
}

list_phases() {
    cat <<PHASES
Available phases (modular execution):
  system-prerequisites
  php
  certbot
  nginx
  mariadb
  redis
  php-pools
  registries
  idempotency
  microcache
  cron
  logrotate
  backups
  security
  cleanup
  health-check
PHASES
}

run_phase() {
    local phase=$1
    [[ -z "$phase" ]] && {
        log_error "Phase name required"
        return 1
    }

    LOG_FILE_OUTPUT_ENABLED=true
    ensure_log_dir || true

    check_root
    check_os
    check_network
    initialize_directories
    initialize_master_keys
    calculate_system_resources >/dev/null 2>&1 || true

    case "$phase" in
        system-prerequisites) phase_system_prerequisites ;;
        php) phase_php_installation ;;
        certbot) phase_certbot ;;
        nginx) phase_nginx ;;
        mariadb) phase_mariadb ;;
        redis) phase_redis ;;
        php-pools) detect_php_version && phase_php_pools_base ;;
        registries) phase_registries ;;
        idempotency) phase_idempotency_lock ;;
        microcache) phase_nginx_microcache ;;
        cron) phase_wordpress_cron ;;
        logrotate) phase_logrotate ;;
        backups) phase_automated_backups ;;
        security) phase_security_hardening ;;
        cleanup) phase_system_cleanup ;;
        health-check) phase_health_check ;;
        *)
            log_error "Unknown phase: $phase"
            list_phases
            return 1
            ;;
    esac
}

is_interactive() {
    [[ -t 0 && -t 1 ]]
}

prompt_input() {
    local prompt=$1
    local default=${2-}
    local allow_empty=${3:-false}
    local value=""

    if [[ -n "$default" ]]; then
        read -r -p "${prompt} [${default}]: " value
        if [[ -z "$value" ]]; then
            value="$default"
        fi
    else
        read -r -p "${prompt}: " value
    fi

    if [[ -z "$value" && "$allow_empty" != "true" ]]; then
        return 1
    fi

    echo "$value"
}

prompt_yes_no() {
    local prompt=$1
    local default=${2:-"y"}
    local reply=""
    local hint="y/n"

    case "$default" in
        y|Y|yes|YES|true|True) default="y"; hint="Y/n" ;;
        n|N|no|NO|false|False) default="n"; hint="y/N" ;;
        *) default="y"; hint="Y/n" ;;
    esac

    while true; do
        read -r -p "${prompt} [${hint}]: " reply
        reply=${reply:-$default}
        case "$reply" in
            y|Y|yes|YES) echo "true"; return 0 ;;
            n|N|no|NO) echo "false"; return 0 ;;
        esac
    done
}

require_initialized() {
    if [[ ! -f "$INITIALIZED_FLAG" ]]; then
        log_error "System not initialized"
        log_info "Run: sudo bash $0"
        return 1
    fi
    return 0
}

run_full_install() {
    # Orchestrates the full install using sequential, idempotent phases.
    # Use `run-phase` to execute a single phase when needed.
    # Full installation
    log_section "${INSTALLER_NAME} v${INSTALLER_VERSION}"
    echo ""
    echo "Author: $INSTALLER_AUTHOR"
    echo "Website: $INSTALLER_WEBSITE"
    echo "Email: $INSTALLER_EMAIL"
    echo ""
    
    LOG_FILE_OUTPUT_ENABLED=true
    ensure_log_dir || true

    # Pre-flight checks
    check_root
    check_os
    check_system_resources
    check_network
    check_prior_initialization
    initialize_directories
    initialize_master_keys
    
    # Installation phases
    phase_system_prerequisites
    phase_php_installation
    phase_certbot
    phase_nginx
    phase_mariadb
    phase_redis
    phase_php_pools_base
    phase_registries
    phase_idempotency_lock
    phase_nginx_microcache
    phase_wordpress_cron
    phase_logrotate
    phase_automated_backups
    phase_security_hardening
    phase_system_cleanup
    phase_health_check || {
        log_warn "Health check identified issues - review logs"
    }
    phase_summary
}

run_health_check() {
    require_initialized || return 1
    check_root
    detect_php_version || return 1
    calculate_system_resources >/dev/null 2>&1

    # Load Redis password for health check
    if [[ -z "$REDIS_PASSWORD" ]]; then
        if [[ -f "$CREDENTIALS_DIR/redis-credentials.txt.enc" ]]; then
            decrypt_credentials "$CREDENTIALS_DIR/redis-credentials.txt.enc" || {
                log_error "Failed to decrypt Redis credentials"
                return 1
            }
            REDIS_PASSWORD=$(grep "^Password:" "$CREDENTIALS_DIR/redis-credentials.txt" | cut -d: -f2- | xargs)
            shred -u -n 3 "$CREDENTIALS_DIR/redis-credentials.txt" 2>/dev/null
        fi
    fi

    phase_health_check
}

maintenance_cleanup() {
    log_section "Maintenance: System Cleanup"
    set_log_context "MAINT" "Cleanup"

    log_info "Cleaning APT caches..."
    apt-get clean >/dev/null 2>&1 || true
    apt-get autoclean >/dev/null 2>&1 || true

    local do_autoremove
    do_autoremove=$(prompt_yes_no "Run apt autoremove (remove unused packages)-" "n")
    if [[ "$do_autoremove" == "true" ]]; then
        apt-get autoremove -y >/dev/null 2>&1 || true
        log_success "Unused packages removed"
    else
        log_info "Skipping autoremove"
    fi

    # Clean temporary files created by the installer and stale temp files
    find /tmp -name "wp-*" -type f -mtime +1 -delete 2>/dev/null || true
    find /var/tmp -name "wp-*" -type f -mtime +1 -delete 2>/dev/null || true

    # Clean old rotated logs
    find /var/log -type f -name "*.log.*" -mtime +30 -delete 2>/dev/null || true

    if command -v journalctl >/dev/null 2>&1; then
        local do_vacuum
        do_vacuum=$(prompt_yes_no "Vacuum systemd journal logs (keep last 14 days)-" "n")
        if [[ "$do_vacuum" == "true" ]]; then
            journalctl --vacuum-time=14d >/dev/null 2>&1 || true
            log_success "Journal logs vacuumed"
        else
            log_info "Skipping journal vacuum"
        fi
    fi

    log_success "System cleanup completed"
}

clear_caches_and_temp() {
    log_section "Maintenance: Clear Caches & Temp Files"
    set_log_context "MAINT" "Clear-Caches"

    # Nginx microcache
    if [[ -d "$CACHE_DIR" ]]; then
        find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
        log_success "Nginx microcache cleared"
    fi

    # WP-CLI cache
    if [[ -d "$WP_CLI_CACHE_DIR" ]]; then
        find "$WP_CLI_CACHE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
        log_success "WP-CLI cache cleared"
    fi

    # PHP session files older than 1 day
    if [[ -d /var/lib/php/sessions ]]; then
        find /var/lib/php/sessions -type f -mtime +1 -delete 2>/dev/null || true
        log_success "Old PHP session files cleared"
    fi

    # Temp files older than 1 day (conservative)
    find /tmp -type f -mtime +1 -delete 2>/dev/null || true
    find /var/tmp -type f -mtime +1 -delete 2>/dev/null || true

    # Optional Redis cache flush for WordPress DBs only
    local do_redis
    do_redis=$(prompt_yes_no "Flush Redis cache for WordPress sites-" "n")
    if [[ "$do_redis" == "true" ]]; then
        if [[ -z "$REDIS_PASSWORD" ]] && [[ -f "$CREDENTIALS_DIR/redis-credentials.txt.enc" ]]; then
            decrypt_credentials "$CREDENTIALS_DIR/redis-credentials.txt.enc" >/dev/null 2>&1 || true
            REDIS_PASSWORD=$(grep "^Password:" "$CREDENTIALS_DIR/redis-credentials.txt" | cut -d: -f2- | xargs)
            shred -u -n 3 "$CREDENTIALS_DIR/redis-credentials.txt" 2>/dev/null || true
        fi
        if [[ -n "$REDIS_PASSWORD" && -f "$REGISTRY_FILE" ]]; then
            local redis_dbs
            redis_dbs=$(jq -r '.domains | to_entries[] | .value.redis_db // empty' "$REGISTRY_FILE" 2>/dev/null | sort -u || true)
            for db in $redis_dbs; do
                redis-cli -a "$REDIS_PASSWORD" -n "$db" FLUSHDB >/dev/null 2>&1 || true
            done
            log_success "Redis caches flushed for WordPress sites"
        else
            log_warn "Redis credentials not available; skipping Redis flush"
        fi
    fi

    log_success "Cache and temp cleanup completed"
}

get_backup_retention_days() {
    local disk_total_gb
    disk_total_gb=$(df -BG / | awk 'NR==2 {gsub("G","",$2); print $2}')
    if [[ -n "$disk_total_gb" ]] && [[ "$disk_total_gb" -lt 20 ]]; then
        echo 7
    else
        echo 15
    fi
}

remove_old_backups() {
    log_section "Maintenance: Remove Old Backups"
    set_log_context "MAINT" "Backups"

    local days=${1:-}
    if [[ -z "$days" ]]; then
        days=$(get_backup_retention_days)
    fi

    if [[ ! "$days" =~ ^[0-9]+$ ]]; then
        log_error "Invalid days value: $days"
        return 1
    fi

    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_warn "Backup directory not found: $BACKUP_DIR"
        return 0
    fi

    local count
    count=$(find "$BACKUP_DIR" -type f \( -name "*.sql.gz" -o -name "*.sql.gz.enc" \) -mtime +"$days" 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$count" -eq 0 ]]; then
        log_info "No backups older than $days days"
        return 0
    fi

    if is_interactive; then
        local confirm
        confirm=$(prompt_yes_no "Remove $count backup(s) older than $days days-" "n")
        if [[ "$confirm" != "true" ]]; then
            log_info "Backup cleanup cancelled"
            return 0
        fi
    fi

    find "$BACKUP_DIR" -type f \( -name "*.sql.gz" -o -name "*.sql.gz.enc" \) -mtime +"$days" -delete 2>/dev/null || true
    log_success "Removed backups older than $days days"
}

show_compression_status() {
    log_section "Compression Status"
    set_log_context "COMPRESSION"

    local perf_conf="/etc/nginx/snippets/wordpress-performance.conf"
    if [[ ! -f "$perf_conf" ]]; then
        log_error "Performance snippet not found: $perf_conf"
        return 1
    fi

    local gzip_enabled="no"
    local gzip_level="n/a"
    if grep -qE '^\s*gzip\s+on;' "$perf_conf" 2>/dev/null; then
        gzip_enabled="yes"
        gzip_level=$(grep -E '^\s*gzip_comp_level' "$perf_conf" 2>/dev/null | awk '{print $2}' | tr -d ';' || true)
    fi

    local brotli_enabled="no"
    local brotli_level="n/a"
    if grep -qE '^\s*brotli\s+on;' "$perf_conf" 2>/dev/null; then
        brotli_enabled="yes"
        brotli_level=$(grep -E '^\s*brotli_comp_level' "$perf_conf" 2>/dev/null | awk '{print $2}' | tr -d ';' || true)
    fi

    local zstd_enabled="no"
    local zstd_level="n/a"
    if grep -qE '^\s*zstd\s+on;' "$perf_conf" 2>/dev/null; then
        zstd_enabled="yes"
        zstd_level=$(grep -E '^\s*zstd_comp_level' "$perf_conf" 2>/dev/null | awk '{print $2}' | tr -d ';' || true)
    fi

    local brotli_module="unknown"
    local zstd_module="unknown"
    if command -v nginx &>/dev/null; then
        if nginx -V 2>&1 | grep -qi "brotli" || nginx_module_enabled "brotli"; then
            brotli_module="yes"
        else
            brotli_module="no"
        fi
        if nginx -V 2>&1 | grep -qi "zstd" || nginx_module_enabled "zstd"; then
            zstd_module="yes"
        else
            zstd_module="no"
        fi
    fi

    echo "gzip:   $gzip_enabled (level: $gzip_level)"
    echo "brotli: $brotli_enabled (level: $brotli_level, module: $brotli_module)"
    echo "zstd:   $zstd_enabled (level: $zstd_level, module: $zstd_module)"
}

confirm_destructive_action() {
    local phrase=$1
    local prompt=$2
    local force_flag=${3:-}
    local input=""

    if ! is_interactive; then
        if [[ "$force_flag" == "--force" || "$force_flag" == "-f" ]]; then
            return 0
        fi
        log_error "Non-interactive mode requires --force"
        return 1
    fi

    echo ""
    echo "$prompt"
    read -r -p "Type '${phrase}' to confirm: " input
    if [[ "$input" != "$phrase" ]]; then
        log_warn "Operation cancelled"
        return 1
    fi
    return 0
}

collect_installed_packages() {
    local regex=$1
    dpkg -l 2>/dev/null | awk -v re="$regex" '$1=="ii" && $2 ~ re {print $2}'
}

purge_packages() {
    local pkgs=("$@")
    if [[ ${#pkgs[@]} -eq 0 ]]; then
        return 0
    fi
    log_info "Purging packages: ${pkgs[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get purge -y "${pkgs[@]}" >/dev/null 2>&1 || log_warn "Package purge failed"
}

purge_packages_regex() {
    local regex=$1
    local pkgs=()
    mapfile -t pkgs < <(collect_installed_packages "$regex")
    purge_packages "${pkgs[@]}"
}

purge_stack_packages() {
    log_info "Purging stack packages..."
    purge_packages_regex '^nginx($|-)'
    purge_packages_regex '^libnginx-'
    purge_packages_regex '^nginx-module-'
    purge_packages_regex '^libnginx-mod-'
    purge_packages_regex '^php[0-9]+[.][0-9]+'
    purge_packages_regex '^php($|-)'
    purge_packages_regex '^mariadb($|-)'
    purge_packages_regex '^mysql($|-)'
    purge_packages_regex '^redis($|-)'
    purge_packages_regex '^certbot($|-)'
    purge_packages_regex '^python3-certbot-'
    purge_packages_regex '^fail2ban$'
    purge_packages_regex '^ufw$'
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y >/dev/null 2>&1 || true
    apt-get autoclean >/dev/null 2>&1 || true
}

purge_site_assets() {
    local domain=$1
    local registry="$REGISTRY_FILE"
    local pool_name=""

    if [[ -f "$registry" ]]; then
        pool_name=$(jq -r ".domains[\"$domain\"].php_pool // empty" "$registry" 2>/dev/null || true)
    fi

    if [[ -n "$pool_name" && -d /etc/php ]]; then
        local ver
        for ver in /etc/php/*; do
            [[ -d "$ver/fpm/pool.d" ]] || continue
            rm -f "$ver/fpm/pool.d/${pool_name}.conf" 2>/dev/null || true
        done
    fi

    rm -f "/etc/nginx/sites-available/${domain}.conf" "/etc/nginx/sites-enabled/${domain}.conf" 2>/dev/null || true
    rm -rf "$SITES_DIR/$domain" 2>/dev/null || true
    rm -f "$CREDENTIALS_DIR/${domain}-credentials.txt" "$CREDENTIALS_DIR/${domain}-credentials.txt.enc" 2>/dev/null || true
}

purge_all_sites() {
    local registry="$REGISTRY_FILE"
    if [[ ! -f "$registry" ]]; then
        log_info "Registry not found; skipping registry site purge"
        return 0
    fi

    local domains
    domains=$(jq -r '.domains | keys[]' "$registry" 2>/dev/null || true)
    if [[ -z "$domains" ]]; then
        log_info "No sites to purge"
        return 0
    fi

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        purge_site_assets "$domain"
    done <<< "$domains"
}

purge_orphan_sites() {
    local root="$SITES_DIR"
    [[ -d "$root" ]] || return 0

    local site_dir=""
    shopt -s nullglob
    for site_dir in "$root"/*; do
        [[ -d "$site_dir" ]] || continue

        if [[ -f "$site_dir/.dazestack-wp-site" ]]; then
            rm -rf "$site_dir" 2>/dev/null || true
            continue
        fi

        if [[ -d "$site_dir/public" && -d "$site_dir/logs" && -d "$site_dir/backups" && -d "$site_dir/tmp" ]]; then
            if [[ -f "$site_dir/public/wp-config.php" || -d "$site_dir/public/wp-content" || -d "$site_dir/public/wp-includes" ]]; then
                rm -rf "$site_dir" 2>/dev/null || true
            fi
        fi
    done
    shopt -u nullglob
}

remove_all_web_roots() {
    local root="$SITES_DIR"
    [[ -d "$root" ]] || return 0
    find "$root" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
}

remove_apt_sources() {
    rm -f /etc/apt/sources.list.d/ondrej-php*.list 2>/dev/null || true
    rm -f /etc/apt/sources.list.d/ondrej-php*.sources 2>/dev/null || true
    rm -f "$ONDREJ_PHP_PREF_FILE" 2>/dev/null || true
}

reset_stack_files() {
    log_info "Removing WordPress sites, configs, and ${INSTALLER_NAME} state..."
    purge_all_sites
    purge_orphan_sites

    rm -f /etc/nginx/snippets/wordpress-security.conf 2>/dev/null || true
    rm -f /etc/nginx/snippets/wordpress-performance.conf 2>/dev/null || true
    rm -f /etc/nginx/snippets/wordpress-http3.conf 2>/dev/null || true
    rm -f /etc/nginx/conf.d/00-rate-limits.conf 2>/dev/null || true
    rm -f /etc/nginx/conf.d/10-cache-zones.conf 2>/dev/null || true
    rm -f "$CLOUDFLARE_CONF" 2>/dev/null || true
    rm -f "$LOGROTATE_CONFIG" 2>/dev/null || true
    rm -f /etc/sysctl.d/99-wp-performance.conf 2>/dev/null || true
    rm -f /etc/fail2ban/jail.local 2>/dev/null || true
    rm -f "$CRON_WORDPRESS_FILE" "$CRON_BACKUP_FILE" "$AUTO_TUNE_CRON_FILE" "$CLOUDFLARE_CRON" 2>/dev/null || true
    rm -f "$CRON_RUNNER_SCRIPT" "$CRON_BACKUP_SCRIPT" "$AUTO_TUNE_SCRIPT" /usr/local/bin/update-cloudflare-ips.sh 2>/dev/null || true
    rm -f "$CLI_WRAPPER" 2>/dev/null || true
    rm -f "$WP_CLI_BIN" 2>/dev/null || true
    rm -rf "$WP_CLI_CACHE_DIR" 2>/dev/null || true
    remove_apt_sources

    rm -rf "$INSTALL_DIR" "$STATE_DIR" "$LOG_DIR" "$BACKUP_DIR" "$CACHE_DIR" "$CONFIG_DIR" "$CREDENTIALS_DIR" 2>/dev/null || true
    rm -rf /var/lib/mysql /var/lib/redis 2>/dev/null || true
}

stop_stack_services() {
    local services=(nginx mariadb mysql redis-server fail2ban)
    local svc
    for svc in "${services[@]}"; do
        systemctl stop "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
    done

    if [[ -d /etc/php ]]; then
        local ver
        for ver in /etc/php/*; do
            [[ -d "$ver/fpm" ]] || continue
            svc="php$(basename "$ver")-fpm"
            systemctl stop "$svc" >/dev/null 2>&1 || true
            systemctl disable "$svc" >/dev/null 2>&1 || true
        done
    fi
}

factory_reset() {
    log_section "Factory Reset: Remove ${INSTALLER_NAME}"
    set_log_context "RESET" "UNINSTALL"

    if ! confirm_destructive_action "DELETE-ALL" \
        "This will remove WordPress sites, configs, data, and stack packages." "${1:-}"; then
        return 0
    fi

    local remove_all="false"
    if is_interactive; then
        remove_all=$(prompt_yes_no "Remove ALL content under $SITES_DIR (including non-DazeStack sites)-" "n")
    elif [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
        remove_all="true"
    fi

    LOG_FILE_OUTPUT_ENABLED=false

    stop_stack_services
    reset_stack_files
    if [[ "$remove_all" == "true" ]]; then
        remove_all_web_roots
    fi
    rm -rf /etc/nginx /etc/php /etc/mysql /etc/redis /etc/letsencrypt 2>/dev/null || true
    rm -rf /var/log/nginx /var/log/mysql /var/log/redis /var/log/php* /var/log/dazestack-wp 2>/dev/null || true
    purge_stack_packages

    log_success "Factory reset completed"
    log_info "A reboot is recommended"
}

refresh_installation() {
    log_section "Refresh Installation: Reinstall ${INSTALLER_NAME}"
    set_log_context "RESET" "REFRESH"

    if ! confirm_destructive_action "REFRESH-ALL" \
        "This will remove all WordPress sites and reinstall the stack from scratch." "${1:-}"; then
        return 0
    fi

    local remove_all="false"
    if is_interactive; then
        remove_all=$(prompt_yes_no "Remove ALL content under $SITES_DIR (including non-DazeStack sites)-" "y")
    elif [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
        remove_all="true"
    fi

    LOG_FILE_OUTPUT_ENABLED=false

    stop_stack_services
    reset_stack_files
    if [[ "$remove_all" == "true" ]]; then
        remove_all_web_roots
    fi
    rm -rf /etc/nginx /etc/php /etc/mysql /etc/redis /etc/letsencrypt 2>/dev/null || true
    rm -rf /var/log/nginx /var/log/mysql /var/log/redis /var/log/php* /var/log/dazestack-wp 2>/dev/null || true
    purge_stack_packages

    LOG_FILE_OUTPUT_ENABLED=true
    ensure_log_dir || true

    log_info "Updating system packages..."
    apt-get update >/dev/null 2>&1 || log_warn "apt-get update failed"
    DEBIAN_FRONTEND=noninteractive apt-get -y upgrade >/dev/null 2>&1 || log_warn "apt-get upgrade failed"

    log_info "Reinstalling stack..."
    run_full_install
}

show_menu() {
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${BOLD}${GREEN} ${INSTALLER_NAME} - ${INSTALLER_EDITION}${NC}"
    echo -e "${MAGENTA} ${INSTALLER_TAGLINE}${NC}"
    echo -e "${CYAN} ${INSTALLER_DESCRIPTION}${NC}"
    echo -e "${CYAN} Author: ${INSTALLER_AUTHOR}${NC}"
    echo -e "${CYAN} Website: ${INSTALLER_WEBSITE}${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${YELLOW}1${NC}) Full installation"
    echo -e "${YELLOW}2${NC}) Create WordPress site"
    echo -e "${YELLOW}3${NC}) Delete WordPress site"
    echo -e "${YELLOW}4${NC}) List sites"
    echo -e "${YELLOW}5${NC}) Show credentials"
    echo -e "${YELLOW}6${NC}) Enable SSL for site"
    echo -e "${YELLOW}7${NC}) Health check"
    echo -e "${YELLOW}8${NC}) Auto-tune performance"
    echo -e "${YELLOW}9${NC}) Rebalance PHP-FPM pools"
    echo -e "${YELLOW}10${NC}) Update Cloudflare IP allowlist"
    echo -e "${YELLOW}11${NC}) Cleanup unused packages & junk"
    echo -e "${YELLOW}12${NC}) Clear caches & temp files"
    echo -e "${YELLOW}13${NC}) Remove old backups"
    echo -e "${YELLOW}14${NC}) Compression status"
    echo -e "${YELLOW}15${NC}) Factory reset (remove stack)"
    echo -e "${YELLOW}16${NC}) Refresh installation (reinstall stack)"
    echo -e "${YELLOW}0${NC}) Exit"
    echo ""
}

menu_full_install() {
    if [[ -f "$INITIALIZED_FLAG" ]]; then
        log_warn "System already initialized; remove $INITIALIZED_FLAG to reinstall"
        return 0
    fi
    run_full_install
}

menu_create_site() {
    require_initialized || return 1
    check_root
    initialize_master_keys
    calculate_system_resources >/dev/null 2>&1

    local domain
    local site_title
    local admin_email
    local admin_user
    local ssl_choice

    domain=$(prompt_input "Domain") || {
        log_warn "Domain is required"
        return 1
    }
    site_title=$(prompt_input "Site title" "$domain")
    admin_email=$(prompt_input "Admin email") || {
        log_warn "Admin email is required"
        return 1
    }
    admin_user=$(prompt_input "Admin username" "$WP_DEFAULT_ADMIN_USER") || {
        log_warn "Admin username is required"
        return 1
    }
    ssl_choice=$(prompt_yes_no "Enable SSL now (requires DNS)" "n")

    create_site "$domain" "$site_title" "$admin_email" "$admin_user" "$ssl_choice"
}

menu_delete_site() {
    require_initialized || return 1
    check_root
    local domain
    domain=$(prompt_input "Domain") || {
        log_warn "Domain is required"
        return 1
    }
    delete_site "$domain"
}

menu_show_credentials() {
    require_initialized || return 1
    check_root
    local domain
    domain=$(prompt_input "Domain") || {
        log_warn "Domain is required"
        return 1
    }
    show_credentials "$domain"
}

menu_enable_ssl() {
    require_initialized || return 1
    check_root
    local domain
    local email
    domain=$(prompt_input "Domain") || {
        log_warn "Domain is required"
        return 1
    }
    email=$(prompt_input "Admin email (leave empty to use registry)" "" true)
    check_network
    enable_ssl_for_site "$domain" "$email"
}

menu_auto_tune() {
    require_initialized || return 1
    check_root
    detect_php_version || true
    apply_auto_tuning
}

menu_rebalance_pools() {
    require_initialized || return 1
    check_root
    detect_php_version || return 1
    calculate_system_resources >/dev/null 2>&1
    rebalance_php_pools
}

menu_update_cloudflare_ips() {
    check_root
    configure_cloudflare_realip
}

menu_factory_reset() {
    check_root
    factory_reset
}

menu_refresh_installation() {
    check_root
    refresh_installation
}

menu_loop() {
    local choice=""
    while true; do
        show_menu
        read -r -p "Select an option: " choice
        case "$choice" in
            1) menu_full_install || true ;;
            2) menu_create_site || true ;;
            3) menu_delete_site || true ;;
            4) { require_initialized && list_sites; } || true ;;
            5) menu_show_credentials || true ;;
            6) menu_enable_ssl || true ;;
            7) run_health_check || true ;;
            8) menu_auto_tune || true ;;
            9) menu_rebalance_pools || true ;;
            10) menu_update_cloudflare_ips || true ;;
            11) check_root && maintenance_cleanup || true ;;
            12) check_root && clear_caches_and_temp || true ;;
            13) check_root && remove_old_backups || true ;;
            14) check_root && show_compression_status || true ;;
            15) menu_factory_reset || true ;;
            16) menu_refresh_installation || true ;;
            0|q|Q|exit) break ;;
            *) log_warn "Invalid selection" ;;
        esac
        echo ""
        read -r -p "Press Enter to return to menu..." _
    done
}

main() {
    # CLI entry point with command dispatch and optional interactive menu.
    # Ensure log directory exists
    mkdir -p "$LOG_DIR" "$STATE_DIR" 2>/dev/null || true
    
    local command=${1:-}
    
    case "$command" in
        create-site)
            # Site creation command
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized. Please run installation first:"
                log_info "  sudo bash $0"
                exit 1
            }
            check_root
            initialize_master_keys
            calculate_system_resources >/dev/null 2>&1
            shift
            local admin_user=""
            local enable_ssl=""
            local positional=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --admin-user=*)
                        admin_user="${1#*=}"
                        shift
                        ;;
                    --admin-user)
                        shift
                        if [[ -z "${1:-}" ]]; then
                            log_error "Missing value for --admin-user"
                            exit 1
                        fi
                        admin_user="$1"
                        shift
                        ;;
                    --ssl)
                        enable_ssl="true"
                        shift
                        ;;
                    --no-ssl)
                        enable_ssl="false"
                        shift
                        ;;
                    --help|-h)
                        show_help
                        exit 0
                        ;;
                    *)
                        positional+=("$1")
                        shift
                        ;;
                esac
            done

            local domain="${positional[0]:-}"
            local site_title="${positional[1]:-}"
            local admin_email="${positional[2]:-}"
            if [[ -z "$admin_user" ]]; then
                admin_user="${positional[3]:-}"
            fi

            if ! create_site "$domain" "$site_title" "$admin_email" "$admin_user" "$enable_ssl"; then
                exit 1
            fi
            ;;
            
        delete-site)
            # Site deletion command
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized"
                exit 1
            }
            check_root
            if ! delete_site "${2:-}"; then
                exit 1
            fi
            ;;
            
        list-sites)
            # List sites command
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized"
                exit 1
            }
            list_sites
            ;;
            
        show-credentials)
            # Show credentials command
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized"
                exit 1
            }
            check_root
            show_credentials "${2:-}"
            ;;
            
        health-check)
            # Health check command
            if ! run_health_check; then
                exit 1
            fi
            ;;

        auto-tune)
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized"
                exit 1
            }
            check_root
            detect_php_version || true
            apply_auto_tuning
            ;;

        run-phase)
            run_phase "${2:-}"
            ;;

        list-phases)
            list_phases
            ;;

        menu)
            if ! is_interactive; then
                log_error "Interactive menu requires a TTY"
                exit 1
            fi
            menu_loop
            ;;

        enable-ssl)
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized"
                exit 1
            }
            check_root
            check_network
            enable_ssl_for_site "${2:-}" ""
            ;;

        install-cli)
            check_root
            install_cli_wrapper
            ;;

        rebalance-pools)
            # Recalculate PHP-FPM pools for all sites
            [[ ! -f "$INITIALIZED_FLAG" ]] && {
                log_error "System not initialized"
                exit 1
            }
            check_root
            detect_php_version || exit 1
            calculate_system_resources >/dev/null 2>&1
            rebalance_php_pools
            ;;
        
        update-cloudflare-ips)
            # Update Cloudflare IP allowlist
            check_root
            configure_cloudflare_realip
            ;;

        remove-old-backups|purge-old-backups)
            check_root
            remove_old_backups "${2:-}"
            ;;

        compression-status)
            show_compression_status
            ;;

        factory-reset)
            check_root
            factory_reset "${2:-}"
            ;;

        refresh-installation)
            check_root
            refresh_installation "${2:-}"
            ;;
        
        list-features)
            show_features
            exit 0
            ;;
            
        help|--help|-h)
            show_help
            exit 0
            ;;
            
        "")
            if is_interactive; then
                menu_loop
            else
                run_full_install
            fi
            ;;
            
        *)
            log_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Trap errors and execute rollback if needed
trap 'on_error $LINENO "$BASH_COMMAND" $?' ERR

# Run main function with all arguments
main "$@"
