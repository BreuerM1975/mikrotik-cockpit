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
  --check        Only verify the installation and the external runtime tools
  --start        Install/update dependencies and start Cockpit
  --remove-menu  Remove the "MikroTik Cockpit" application menu entry again
  --help         Show this help

Without an option the local Python virtual environment is created or
updated and a "MikroTik Cockpit" menu entry is created for the current
user, but the service is not started.
EOF
}

# Application menu entry for the current user only (no sudo): a .desktop file that calls the
# starter. Cockpit then starts with one click from the menu, no terminal needed.
menu_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
menu_file="$menu_dir/mikrotik-cockpit.desktop"

install_menu_entry() {
  mkdir -p "$menu_dir"
  cat > "$menu_file" <<DESKTOP
[Desktop Entry]
Type=Application
Name=MikroTik Cockpit
Comment=Local web UI for MikroTik RouterOS
Exec="$script_dir/start-cockpit.sh"
Icon=$script_dir/assets/cockpit-icon.svg
Terminal=false
Categories=Network;
Keywords=MikroTik;RouterOS;Router;
DESKTOP
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$menu_dir" >/dev/null 2>&1 || true
  fi
  echo "Menu entry created: $menu_file"
}

remove_menu_entry() {
  if [[ -f "$menu_file" ]]; then
    rm -f "$menu_file"
    echo "Menu entry removed: $menu_file"
  else
    echo "No menu entry present: $menu_file"
  fi
}

mode="install"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  --start) mode="start" ;;
  --remove-menu) remove_menu_entry; exit 0 ;;
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
  if [[ -f "$menu_file" ]]; then
    echo "Menu entry present: $menu_file"
  else
    echo "Note: no menu entry yet; ./install-cockpit.sh without options creates it."
  fi
  exit 0
fi

install_menu_entry

if [[ "$mode" == "start" ]]; then
  exec "$script_dir/start-cockpit.sh"
fi

echo "Start it with: $script_dir/start-cockpit.sh"
