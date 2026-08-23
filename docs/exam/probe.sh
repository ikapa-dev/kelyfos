#!/usr/bin/env bash
set -uo pipefail
export PATH="$HOME/exam/bin:$PATH"
work="$HOME/exam/probe"; rm -rf "$work"; mkdir -p "$work"; cd "$work"
trap 'kelyfos team down >/dev/null 2>&1 || true; pkill -f "kelyfos team up" 2>/dev/null || true' EXIT

cat > kelyfos.toml <<'TOML'
[team]
name = "probe"
[[team.agent]]
name  = "master"
image = "dev"
[[team.agent]]
name  = "worker"
image = "dev"
count = 2
[[team.edge]]
from = "master"
to   = "worker-*"
[team.store]
enabled = true
TOML

kelyfos team up >up.log 2>&1 &
for _ in $(seq 1 600); do grep -q 'team up in' up.log && break; sleep 0.25; done
grep -q 'team up in' up.log || { cat up.log; exit 1; }
echo "team is up"

sandbox() { python3 -c "
import json,sys
a=json.load(open('$HOME/.cache/kelyfos/run/team.json'))['agents']
print([x['sandbox'] for x in a if x['name']=='$1'][0])"; }

raw() {  # raw <sandbox-id> <tool> <args-json> <hold-seconds>
  { printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
    sleep "$4"
  } | timeout 90 kelyfos mcp --sandbox "$1" 2>&1 | tail -2
}

echo
echo "########## PROBE 1: what team.json actually contains ##########"
python3 -m json.tool "$HOME/.cache/kelyfos/run/team.json"

echo
echo "########## PROBE 2: kelyfos mcp with NO --sandbox while a team is up ##########"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"p","version":"1"}}}' \
  | timeout 20 kelyfos mcp 2>&1 | tail -3
echo "exit=$?"

echo
echo "########## PROBE 3: kelyfos exec with NO --sandbox while a team is up ##########"
timeout 20 kelyfos exec 'echo hi' 2>&1 | tail -3
echo "exit=$?"

echo
echo "########## PROBE 4: blocking team_ask, channel NOT held open long enough ##########"
echo "(ask master with timeout_ms 20000, but close stdin after 1s and nobody replies)"
raw "$(sandbox worker-1)" team_ask '{"to":"master","body":"held too briefly?","timeout_ms":20000}' 1

echo
echo "########## PROBE 5: team_recv on an empty window ##########"
raw "$(sandbox worker-2)" team_recv '{"timeout_ms":2000}' 4

echo
echo "########## PROBE 6: team_reply with a bogus correlate tag ##########"
raw "$(sandbox master)" team_reply '{"correlate":"deadbeefdeadbeef","body":"nope"}' 3

echo
echo "########## PROBE 7: team_send to an agent that does not exist ##########"
raw "$(sandbox master)" team_send '{"to":"nobody","body":"hello"}' 3

echo
echo "########## PROBE 8: does worker-1 see team_spawn (no budget declared)? ##########"
{ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"p","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  sleep 3
} | timeout 30 kelyfos mcp --sandbox "$(sandbox worker-1)" 2>/dev/null | tail -1 \
  | python3 -c 'import json,sys; print(sorted(t["name"] for t in json.load(sys.stdin)["result"]["tools"]))'

echo
echo "########## PROBE 9: log --session <agent sandbox id> while team is up ##########"
kelyfos log --session "$(sandbox worker-1)" 2>&1 | head -4

kelyfos team down
