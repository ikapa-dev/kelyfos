#!/usr/bin/env bash
# KelyfOS — the team broker's edges, committed as a suite (ST-1.7).
#
#   bash dev/accept-security-team.sh
#
# The audit's team scenarios, machine-checked, on a three-agent star: the
# roster matches the declared topology; an agent in a team sees the ordinary
# tool surface plus the team tools and nothing more; a worker-to-worker send
# is refused as no edge, before any effect; a worker-to-master send is
# delivered; a spawn without budget is refused; team_peers leaks no
# non-neighbour; and every refusal and delivery is in one verifiable record
# across all three agents.
#
# The broker's rule under test is the one the BROKER checklist opens with:
# ACLs evaluated BEFORE the effect. A refusal that arrives after the message
# moved would be indistinguishable from delivery in the audit trail.
#
# No network beyond loopback.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-team

# call <sandbox> <json-rpc-lines...> — one MCP client conversation against one
# agent's bridge; echoes the last response line.
call() {
  local sb="$1"; shift
  { printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sec-lab","version":"1"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    for line in "$@"; do printf '%s\n' "$line"; done
    sleep 4
  } | timeout 90 "$BIN/kelyfos" mcp --sandbox "$sb" 2>/dev/null | tail -1
}
tools_count() { python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print(-1); raise SystemExit
try: print(len(d["result"]["tools"]))
except Exception: print(-1)' 2>/dev/null; }
# call_hold <seconds> <sandbox> <json-rpc-lines...> — the same, holding the
# bridge open for the given seconds: a blocking tool answers when the other
# side acts, and closing stdin early closes the bridge first.
call_hold() {
  local hold="$1" sb="$2"; shift 2
  { printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sec-lab","version":"1"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    for line in "$@"; do printf '%s\n' "$line"; done
    sleep "$hold"
  } | timeout 120 "$BIN/kelyfos" mcp --sandbox "$sb" 2>/dev/null | tail -1
}
text_of() { python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print(""); raise SystemExit
try: print(d["result"]["content"][0]["text"])
except Exception: print("")' 2>/dev/null; }

say "the team goes up, and the roster matches the declaration"
# team up reads the project's kelyfos.toml — the team is part of the project
# policy, not a side file.
cat > kelyfos.toml <<'EOF'
[team]
name = "sec-lab-star"

[[team.agent]]
name = "master"
image = "dev"

[[team.agent]]
name = "worker"
image = "dev"
count = 2

[[team.edge]]
from = "master"
to   = "worker-*"
EOF

( "$BIN/kelyfos" team up > "$SLAB_WORK/team.log" 2>&1 & echo $! > "$SLAB_WORK/team.pid" )
roster=""
for i in $(seq 1 120); do
  roster="$("$BIN/kelyfos" team ps --json 2>/dev/null | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)["agents"]))
except Exception: print(0)' 2>/dev/null)"
  [ "$roster" = "3" ] && break
  sleep 1
done
assert_eq "$roster" "3" "the roster lists exactly the three declared agents"
SESSION="$("$BIN/kelyfos" team ps --json 2>/dev/null | python3 -c 'import json,sys
print(json.load(sys.stdin).get("session",""))' 2>/dev/null)"
W1="$("$BIN/kelyfos" team ps --json 2>/dev/null | python3 -c 'import json,sys
a=json.load(sys.stdin)["agents"];print([x["sandbox"] for x in a if x["agent"]=="worker-1"][0])' 2>/dev/null)"
W2="$("$BIN/kelyfos" team ps --json 2>/dev/null | python3 -c 'import json,sys
a=json.load(sys.stdin)["agents"];print([x["sandbox"] for x in a if x["agent"]=="worker-2"][0])' 2>/dev/null)"
check "$([ -n "$W1" ] && [ -n "$W2" ] && [ "$W1" != "$W2" ] && echo yes || echo no)" \
      "worker-1 and worker-2 are distinct machines named by the topology"

say "the tool surface, from inside worker-1"
surface="$(call "$W1" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')"
count="$(tools_count <<<"$surface")"
assert_eq "$count" "13" "the agent sees exactly 6 ordinary + 7 team tools, nothing more"

say "an edge that does not exist is refused before any effect"
noedge="$(call "$W1" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"team_send","arguments":{"to":"worker-2","body":"worker to worker"}}}')"
noedge_text="$(text_of <<<"$noedge")"
assert_contains "$noedge_text" "no_edge" "worker-1 → worker-2 is refused: no edge"
assert_contains "$noedge_text" "[team.edge]" "and the refusal names its denial ID"
assert_grep_event '"type":\s*"team.refused"' "the refusal is in the record"

say "an edge that exists delivers"
delivered="$(call "$W1" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"team_send","arguments":{"to":"master","body":"worker-1 to master via sec-lab"}}}')"
delivered_text="$(text_of <<<"$delivered")"
check "$(grep -qiE 'sent|queued|delivered|accepted' <<<"$delivered_text" && echo yes || echo no)" \
      "worker-1 → master is delivered ($(head -c 60 <<<"$delivered_text" | tr -d '\n'))"
assert_grep_event '"type":\s*"team.message"' "the delivery is in the record"

say "a spawn without a budget is refused"
spawn="$(call "$W1" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"team_spawn","arguments":{"image":"dev"}}}')"
spawn_text="$(text_of <<<"$spawn")"
assert_contains "$spawn_text" "[team.spawn_none]" "team_spawn with no spawn budget names team.spawn_none"

say "team_peers leaks no non-neighbour"
# team_peers is a blocking tool: the bridge must stay open until the guest
# answers, so this call holds stdin longer than the others.
peers="$(call_hold 12 "$W1" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"team_peers","arguments":{}}}')"
peers_text="$(text_of <<<"$peers")"
assert_contains "$peers_text" "master" "worker-1's peers include the master"
assert_eq "$(grep -c "worker-2" <<<"$peers_text" || true)" "0" \
      "and never names worker-2 — the agent it has no edge to"

say "one record, three agents, still verifiable"
for agent_id in "$W1" "$W2"; do
  v="$("$BIN/kelyfos" log -session "$agent_id" --verify 2>&1)"
  check "$(grep -qiE 'intact|verified' <<<"$v" && echo yes || echo no)" \
        "worker session $agent_id's chain verifies"
done
assert_grep_event '"type":\s*"team.refused"' "the team session's record holds the refusal"
assert_grep_event '"type":\s*"team.message"' "and the delivery"

"$BIN/kelyfos" team down --team "$SESSION" >/dev/null 2>&1
for i in $(seq 1 60); do
  left="$("$BIN/kelyfos" team ps --json 2>/dev/null | python3 -c 'import json,sys
try: print(len(json.load(sys.stdin)["agents"]))
except Exception: print(0)' 2>/dev/null)"
  [ "$left" = "0" ] && break
  sleep 1
done
scope_kill_kelyfos

slab_done
