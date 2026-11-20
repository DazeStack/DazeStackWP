#!/usr/bin/env bash

# Test script for php_package_is_optional function in dazestack-wp.sh

if [[ -z "${BASH_VERSINFO[0]:-}" ]] || [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    echo "Notice: Unit tests require Bash 4+ (Ubuntu 24.04/26.04 or Homebrew bash). Current: ${BASH_VERSION:-unknown}. Skipping on legacy Bash 3.2."
    exit 0
fi

# Mock required environment/functions that dazestack-wp.sh might need or trigger
export LOG_LEVEL=0
export LOG_FILE_OUTPUT_ENABLED=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the script directly (now safe because main is guarded by BASH_SOURCE check)
source "${SCRIPT_DIR}/dazestack-wp.sh" > /dev/null 2>&1 || true

# Override the error trap to prevent exit on non-zero return codes from functions
trap - ERR
set +e

# Test helper
assert_optional() {
    local pkg=$1
    local expected=$2
    local php_ver=$3
    shift 3
    local opt_pkgs=("$@")

    # Set up mocks
    PHP_VERSION="$php_ver"
    PHP_OPTIONAL_PACKAGES=("${opt_pkgs[@]}")

    php_package_is_optional "$pkg"
    local actual=$?

    if [[ $actual -eq $expected ]]; then
        echo -e "[\033[0;32mPASS\033[0m] pkg=$pkg version=$php_ver opts=(${opt_pkgs[*]}) expected=$expected actual=$actual"
    else
        echo -e "[\033[0;31mFAIL\033[0m] pkg=$pkg version=$php_ver opts=(${opt_pkgs[*]}) expected=$expected actual=$actual"
        exit 1
    fi
}

echo "Running unit tests for php_package_is_optional..."

# Case 1: Package is optional and matches version
assert_optional "php8.3-common" 0 "8.3" "common" "intl"

# Case 2: Package is optional but doesn't match version prefix
assert_optional "php8.2-common" 1 "8.3" "common" "intl"

# Case 3: Package matches version but is NOT in optional list
assert_optional "php8.3-mysql" 1 "8.3" "common" "intl"

# Case 4: Package matches version and is at the end of optional list
assert_optional "php8.5-zip" 0 "8.5" "common" "gd" "zip"

# Case 5: Empty optional list
assert_optional "php8.5-common" 1 "8.5"

# Case 6: Package name matches version exactly but has nothing after hyphen
assert_optional "php8.5-" 1 "8.5" "common"

# Case 7: Package name doesn't start with php prefix
assert_optional "something-php8.5-common" 1 "8.5" "common"

echo "All tests for php_package_is_optional passed!"
