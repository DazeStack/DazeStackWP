#!/usr/bin/env bash
# Unit tests for input validation, sanitization, and safety guards in dazestack-wp.sh

if [[ -z "${BASH_VERSINFO[0]:-}" ]] || [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    echo "Notice: Unit tests require Bash 4+ (Ubuntu 24.04/26.04 or modern bash). Skipping on legacy Bash 3.2."
    exit 0
fi

export LOG_LEVEL=0
export LOG_FILE_OUTPUT_ENABLED=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source dazestack-wp.sh directly
source "${SCRIPT_DIR}/dazestack-wp.sh" > /dev/null 2>&1 || true

trap - ERR
set +e

pass_count=0
fail_count=0

assert_true() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "[\033[0;32mPASS\033[0m] $desc"
        ((pass_count++))
    else
        echo -e "[\033[0;31mFAIL\033[0m] $desc"
        ((fail_count++))
    fi
}

assert_false() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "[\033[0;31mFAIL\033[0m] $desc (expected failure but command succeeded)"
        ((fail_count++))
    else
        echo -e "[\033[0;32mPASS\033[0m] $desc"
        ((pass_count++))
    fi
}

echo "Running DazeStack WP Safety & Validation Test Suite..."

# 1. Domain validation tests
assert_true "Valid domain: example.com" 'validate_domain "example.com"'
assert_true "Valid subdomain: sub.example.co.uk" 'validate_domain "sub.example.co.uk"'
assert_false "Reject empty domain" 'validate_domain ""'
assert_false "Reject path traversal in domain" 'validate_domain "../evil.com"'
assert_false "Reject command injection in domain" 'validate_domain "evil.com;rm -rf /"'
assert_false "Reject SQL injection in domain" 'validate_domain "evil.com'\'' OR 1=1--"'

# 2. Database name sanitization tests
db_res=$(sanitize_db_name "blog.example.com")
if [[ "$db_res" == "wp_blog_example_com" ]]; then
    echo -e "[\033[0;32mPASS\033[0m] DB name sanitized to: $db_res"
    ((pass_count++))
else
    echo -e "[\033[0;31mFAIL\033[0m] DB name expected 'wp_blog_example_com', got '$db_res'"
    ((fail_count++))
fi

# 3. Safe cleanup guard tests
assert_false "Reject cleaning root directory /" 'safe_cleanup "/"'
assert_false "Reject cleaning /var" 'safe_cleanup "/var"'
assert_false "Reject cleaning /var/www base directory itself" 'safe_cleanup "/var/www"'
assert_false "Reject cleaning /var/www/ with trailing slash" 'safe_cleanup "/var/www/"'
assert_false "Reject cleaning /var/backups/dazestack-wp base directory itself" 'safe_cleanup "/var/backups/dazestack-wp"'

# 4. Memory limit bound tests
calculate_system_resources >/dev/null 2>&1
if [[ "$PHP_MEMORY_LIMIT" =~ ^(128M|256M|512M)$ ]]; then
    echo -e "[\033[0;32mPASS\033[0m] PHP_MEMORY_LIMIT bounded safely: $PHP_MEMORY_LIMIT"
    ((pass_count++))
else
    echo -e "[\033[0;31mFAIL\033[0m] PHP_MEMORY_LIMIT outside safe bounds: $PHP_MEMORY_LIMIT"
    ((fail_count++))
fi

echo "Test summary: $pass_count passed, $fail_count failed"
if [[ $fail_count -gt 0 ]]; then
    exit 1
fi
exit 0
