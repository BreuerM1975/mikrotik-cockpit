#!/usr/bin/env bash
set -euo pipefail

# Connect model like WinBox: this script only starts the service and opens the connect screen.
# There is no hard-coded router connection -- you type address, username and password into the
# browser, exactly as you would in WinBox.
#
# After running the local installer the starter uses the project-local virtual environment.
# Without it, the plain system Python remains as a fallback for development.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$script_dir"
app_path="$project_dir/app/backend/src/app.py"
python_bin="$project_dir/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  python_bin="$(command -v python3)"
fi

if [[ ! -f "$app_path" ]]; then
  echo "Error: $app_path not found -- this script is not in the project folder." >&2
  exit 1
fi

missing=()
for command in python3 curl sshpass ssh ssh-keyscan ssh-keygen fuser ps grep; do
  if ! command -v "$command" >/dev/null 2>&1; then
    missing+=("$command")
  fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Error: missing required tools: ${missing[*]}." >&2
  echo "Install the missing Linux packages and start Cockpit again." >&2
  exit 1
fi
if ! "$python_bin" -c 'import flask' >/dev/null 2>&1; then
  echo "Error: the Python module Flask is missing." >&2
  echo "Install the dependencies with: $project_dir/install-cockpit.sh" >&2
  exit 1
fi

for optional_command in scp wg xdg-open; do
  if ! command -v "$optional_command" >/dev/null 2>&1; then
    echo "Note: $optional_command is missing; the feature that relies on it is unavailable." >&2
  fi
done

export COCKPIT_BACKEND_PORT="8787"

# Only stop an earlier Cockpit process on this port, never some unrelated service that happens
# to hold it ("fuser -k" on its own does not check what it is killing).
existing_pids="$(fuser 8787/tcp 2>/dev/null || true)"
if [[ -n "$existing_pids" ]]; then
  read -r -a pid_list <<< "$existing_pids"
  for existing_pid in "${pid_list[@]}"; do
    process_args="$(ps -p "$existing_pid" -o args= 2>/dev/null || true)"
    if [[ "$process_args" == *"app/backend/src/app.py"* ]]; then
      kill "$existing_pid" 2>/dev/null || true
    else
      echo "Error: port 8787 is held by an unrelated process (PID $existing_pid), aborting." >&2
      exit 1
    fi
  done
  sleep 0.3
fi

"$python_bin" "$app_path" &
cockpit_pid=$!
trap 'kill "$cockpit_pid" 2>/dev/null || true' EXIT

ready=""
for attempt in {1..20}; do
  if curl -fsS --max-time 1 http://127.0.0.1:8787/ >/dev/null; then
    ready="1"
    break
  fi
  sleep 0.2
done
if [[ -z "$ready" ]]; then
  echo "Error: the backend did not answer within 4 seconds, not opening the browser." >&2
  exit 1
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://127.0.0.1:8787/" >/dev/null 2>&1 &
else
  echo "Cockpit is running at: http://127.0.0.1:8787/"
fi
wait "$cockpit_pid"
