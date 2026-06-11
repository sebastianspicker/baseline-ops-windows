#!/usr/bin/env bash
set -euo pipefail

project_dir="${SRC:-/src}/win-mdm-security-hardening-kit"
out_dir="${OUT:-/out}"

cd "$project_dir"
npm ci

mkdir -p "$out_dir"
cat > "$out_dir/profile_validation_fuzz" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cd "${SRC:-/src}/win-mdm-security-hardening-kit"
npm run fuzz
EOF

chmod +x "$out_dir/profile_validation_fuzz"
