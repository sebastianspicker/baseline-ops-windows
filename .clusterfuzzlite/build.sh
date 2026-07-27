#!/usr/bin/env bash
# Produces the ClusterFuzzLite entrypoint in $OUT; dependency installation is
# kept inside the pinned build image so the resulting target is reproducible.
set -euo pipefail

project_dir="${SRC:-/src}/baselineops-windows"
out_dir="${OUT:-/out}"

cd "$project_dir"
npm ci

mkdir -p "$out_dir"
cat > "$out_dir/profile_validation_fuzz" <<'EOF'
#!/usr/bin/env bash
# Runs the repository fuzz command from its source root because the validator
# resolves profiles and scripts relative to the checked-out kit.
set -euo pipefail

cd "${SRC:-/src}/baselineops-windows"
npm run fuzz
EOF

chmod +x "$out_dir/profile_validation_fuzz"
