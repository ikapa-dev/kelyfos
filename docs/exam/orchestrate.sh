#!/usr/bin/env bash
# orchestrate.sh — boot a three-agent KelyfOS team, make one agent ask another a
# question and wait for the answer, then export the session transcript.
#
# Built only from ~/exam/llms-full.txt: cookbook recipe 5 ("Three agents, an ask
# round-trip, and a refused edge"), the CLI reference for `kelyfos team up` and
# `kelyfos log --export`, and the MCP tools reference for team_ask/team_reply.
set -euo pipefail

export PATH="$HOME/exam/bin:$PATH"
work="$HOME/exam/run"
export_path="$HOME/exam/team-transcript.html"

rm -rf "$work"; mkdir -p "$work"; cd "$work"
trap 'kelyfos team down >/dev/null 2>&1 || true; pkill -f "kelyfos team up" 2>/dev/null || true' EXIT

# ---------------------------------------------------------------- the policy
# Three agents: one master and two workers. The edge list is a star, so the two
# workers have no path to each other. [[team.edge]] is bidirectional by default,
# which is what lets worker-1 ask the master a question.
cat > kelyfos.toml <<'TOML'
[team]
name = "exam"
record_payloads = true

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

echo "== booting the team =="
kelyfos team up >up.log 2>&1 &
for _ in $(seq 1 600); do grep -q 'team up in' up.log && break; sleep 0.25; done
grep -q 'team up in' up.log || { echo "FAILED: team never reported ready"; cat up.log; exit 1; }
cat up.log
echo
kelyfos team ps
echo

# ------------------------------------------------------------- the MCP helper
# `kelyfos mcp` bridges stdio to one guest's MCP server. A blocking tool answers
# when the other side acts, so the channel has to be held open past the write.
sandbox() { python3 -c "
import json,sys
a=json.load(open('$HOME/.cache/kelyfos/run/team.json'))['agents']
print([x['sandbox'] for x in a if x['name']=='$1'][0])"; }

call() {  # call <agent> <tool> <args-json> [seconds to hold the channel open]
  { printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"exam","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
    sleep "${4:-5}"
  } | timeout 90 kelyfos mcp --sandbox "$(sandbox "$1")" 2>/dev/null | tail -1
}
text() { python3 -c 'import json,sys
d=json.load(sys.stdin); c=d.get("result",{}).get("content",[])
print(c[0].get("text","") if c else d)'; }
field() { python3 -c "import json,sys
print(json.load(sys.stdin).get('result',{}).get('structuredContent',{}).get('$1',''))"; }

echo "== who can master reach =="
call master team_peers '{}' 3 | text

echo
echo "== master hands worker-1 a task =="
call master team_send '{"to":"worker-1","body":"count the regular files in /etc"}' 3 | text

echo "== worker-1 takes it =="
call worker-1 team_recv '{"timeout_ms":10000}' 3 | text

# ------------------------------------------- the required ask round-trip
echo
echo "== worker-1 asks the master a question and BLOCKS on the answer =="
call worker-1 team_ask '{"to":"master","body":"only regular files, or directories too?","timeout_ms":30000}' 20 > ask.out &
asker=$!
sleep 3

q="$(call master team_recv '{"timeout_ms":15000}' 3)"
echo "  master received: $(echo "$q" | text)"
correlate="$(echo "$q" | field correlate)"
echo "  correlate tag:   $correlate"
call master team_reply "{\"correlate\":\"$correlate\",\"body\":\"regular files only\"}" 3 | text
wait "$asker"
echo "  worker-1's blocked ask returned: $(text < ask.out)"

echo
echo "== worker-1 does the work and publishes it to the team store =="
call worker-1 exec '{"command":"ls -l /etc | grep -c \"^-\""}' 5 | text
call worker-1 team_store_put '{"key":"findings/worker-1","value":"counted, regular files only"}' 3 | text
call master team_store_get '{"key":"findings/worker-1"}' 3 | text

echo
echo "== an edge that was never declared is refused =="
call worker-1 team_send '{"to":"worker-2","body":"psst"}' 3 | text

# ------------------------------------------------------- export the transcript
echo
echo "== tearing the team down =="
kelyfos team down
sleep 1

echo
echo "== the record =="
kelyfos log | grep -E 'team' || true
echo
kelyfos log --verify
echo
kelyfos log --export "$export_path"
ls -l "$export_path"
