#!/usr/bin/env bash
set -euo pipefail

# Local Linux installer for MikroTik Cockpit.
# It only touches the project environment (.venv). It installs no system packages and never
# runs sudo.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="$script_dir/.venv"
requirements_file="$script_dir/app/backend/requirements.txt"

usage() {
  cat <<'EOF'
Usage: ./install-cockpit.sh [OPTION]

Options:
  --check   Only verify the installation and the external runtime tools
  --start   Install/update dependencies and start Cockpit
  --help    Show this help

Without an option the local Python virtual environment is created or
updated, but the service is not started.
EOF
}

mode="install"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  --start) mode="start" ;;
  --help|-h) usage; exit 0 ;;
  *) echo "Error: unknown option: $1" >&2; usage >&2; exit 2 ;;
esac

if [[ ! -f "$requirements_file" ]]; then
  echo "Error: requirements.txt not found: $requirements_file" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is missing. Install Python 3.10 or newer via your package manager." >&2
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "Error: the Python module venv is missing." >&2
  echo "Debian/Ubuntu: sudo apt install python3-venv" >&2
  echo "Fedora: sudo dnf install python3" >&2
  echo "Arch: sudo pacman -S python" >&2
  exit 1
fi

python_bin="$venv_dir/bin/python"
if [[ "$mode" == "check" && ! -x "$python_bin" ]]; then
  echo "Error: no virtual environment found: $venv_dir" >&2
  echo "Run $script_dir/install-cockpit.sh without options first." >&2
  exit 1
fi
if [[ ! -x "$python_bin" ]]; then
  echo "Creating Python virtual environment: $venv_dir"
  python3 -m venv "$venv_dir"
fi

if [[ "$mode" != "check" ]]; then
  echo "Installing Python dependencies from $requirements_file"
  "$python_bin" -m pip install --disable-pip-version-check -r "$requirements_file"
else
  echo "Checking existing Python environment: $venv_dir"
fi

if ! "$python_bin" -c 'import flask' >/dev/null 2>&1; then
  echo "Error: Flask could not be imported in the virtual environment." >&2
  exit 1
fi

required_commands=(curl sshpass ssh ssh-keyscan ssh-keygen fuser ps grep)
missing_commands=()
for command in "${required_commands[@]}"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    missing_commands+=("$command")
  fi
done

if [[ ${#missing_commands[@]} -gt 0 ]]; then
  echo "Note: system tools still missing for starting Cockpit: ${missing_commands[*]}" >&2
  echo "Debian/Ubuntu: sudo apt install curl sshpass openssh-client procps psmisc grep" >&2
  echo "Fedora: sudo dnf install curl sshpass openssh-clients procps-ng psmisc grep" >&2
  echo "Arch: sudo pacman -S curl sshpass openssh procps psmisc grep" >&2
  if [[ "$mode" == "start" || "$mode" == "check" ]]; then
    echo "Aborting: required tools are missing; the installation is not ready to start." >&2
    exit 1
  fi
else
  echo "System tools: complete"
fi

for optional_command in scp wg xdg-open; do
  if command -v "$optional_command" >/dev/null 2>&1; then
    echo "Optional: $optional_command present"
  else
    echo "Optional: $optional_command missing; the related feature is limited"
  fi
done

echo "Cockpit installation verified: $venv_dir"
if [[ "$mode" == "check" ]]; then
  exit 0
fi

if [[ "$mode" == "start" ]]; then
  exec "$script_dir/start-cockpit.sh"
fi

echo "Start it with: $script_dir/start-cockpit.sh"
