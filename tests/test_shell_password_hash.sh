#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$PROJECT_ROOT/lib/utils.sh"

password="P@ss word'with\"quotes"
password_hash="$(generate_web_password_hash "$password")"

python3 - "$password_hash" "$password" <<'PYEOF'
import sys
from werkzeug.security import check_password_hash

password_hash = sys.argv[1]
password = sys.argv[2]

assert password_hash, "password hash should not be empty"
assert check_password_hash(password_hash, password), "generated hash does not validate"
PYEOF
