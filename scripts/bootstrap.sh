#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv_dir="${project_dir}/.venv"

python3 -m venv "${venv_dir}"
"${venv_dir}/bin/python" -m pip install --upgrade pip
"${venv_dir}/bin/python" -m pip install -e "${project_dir}"

if [[ ! -f "${project_dir}/sentinelgate.toml" ]]; then
  "${venv_dir}/bin/sentinelgate" init --output "${project_dir}/sentinelgate.toml"
fi

echo "SentinelGate is ready."
echo "Run: ${venv_dir}/bin/sentinelgate --config ${project_dir}/sentinelgate.toml demo"

