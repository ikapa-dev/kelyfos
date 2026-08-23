# KelyfOS cookbook

Seven recipes, each one complete, each one runnable as it stands.

These are not illustrations. `bash dev/cookbook.sh` extracts every script below
and runs it on a real machine, and CI runs the same thing — so a recipe that
stops working fails the build rather than failing a stranger who trusted it
(F-D4, E3-3). What you copy is what was executed.

**Before any of them.** You need Linux with `/dev/kvm`, Firecracker, the
`kelyfos` binary on your `PATH`, and the `dev` image. The
[quickstart](../README.md#quickstart) is four commands, and `kelyfos doctor`
will tell you which of the four you still owe it.

A note that will save you an hour. `kelyfos run`, `kelyfos fork` and
`kelyfos team up` all **hold their machines for as long as they run**, the way
`docker run` without `-d` does. Only `run` has a trailing-command form —
`kelyfos run [flags] -- <command>` boots the sandbox, runs that command on the
*host* with `KELYFOS_SANDBOX` set so `kelyfos exec` attaches to the right
machine, then tears everything down and exits with the command's own status.
That is the shape most of these recipes use, because it needs no signal handling
and no polling. For `fork` and `team up` the recipes background the process and
wait for the line that says the machines are ready.

---

## 1. Run one sandbox

The shortest useful thing there is. The guest has no shell login, no SSH and —
with no `--allow` — no network interface at all.

<!-- recipe: one-sandbox -->

```bash
set -euo pipefail

# The shortest useful thing: boot a sandbox, run something in it, tear it down.
# `run -- <command>` gives the sandbox the command's lifetime, exports
# KELYFOS_SANDBOX so `kelyfos exec` attaches to the right machine, and exits with
# the command's own status.
#
# Without --allow this machine has no network interface at all. Not a firewalled
# one: none.
kelyfos run --image dev -- bash -c '
  set -e
  kelyfos exec "uname -a"
  kelyfos exec "cat /etc/os-release" | grep "^ID="

  # The root filesystem is read-only with a tmpfs overlay, so anything written
  # outside /work lives in guest memory and dies with the sandbox.
  kelyfos exec "echo hello > /tmp/note && cat /tmp/note"

  # There is no shell login and no SSH: exec goes over a vsock channel to the
  # supervisor, which is PID 1. This is the whole interface.
  kelyfos exec "ps -o pid,comm | head -3"
'

# To keep one running instead — for an interactive session or an agent you drive
# yourself — background it and stop it with Ctrl-C:
#
#   kelyfos run --image dev &
#   kelyfos exec 'uname -a'
#   # Ctrl-C in the first terminal tears it down and syncs any workspace back.
echo "sandbox ran and was torn down"
```

---

## 2. Allowlist a domain, and inject a credential the guest never sees

`--allow` is what creates a network interface; without it there is nothing to
misconfigure. `--secret NAME@domain` keeps the value on the host: the proxy
terminates TLS for that domain alone, attaches the header, and forwards. An
agent that is completely compromised can still *use* the credential against the
domain it is bound to — that is what binding means — but it cannot read it, keep
it, or send it anywhere else.

The token below is deliberately not real, which is the point: the guarantee does
not depend on the value being valid. With a real one the same call returns 200
instead of 401 and nothing else changes.

<!-- recipe: allowlist-and-secret -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# The value stays on the host. This one is deliberately not a real token,
# because the point of the recipe is that whatever it is, the guest never sees
# it: with a real one the same call comes back 200 instead of 401.
export GITHUB_TOKEN="not-a-real-token"

# --allow creates the network interface. Without it there is none at all — not a
# firewalled one, none — so there is no rule that has to hold for the guarantee
# to be true. --secret binds a credential to one domain: the proxy terminates
# TLS for that domain only, attaches the header, and forwards.
kelyfos run --image dev \
  --allow api.github.com \
  --secret GITHUB_TOKEN@api.github.com -- bash -c '
  set -e

  echo "== an allowlisted domain is reachable, and the proxy authenticated it =="
  kelyfos exec "curl -s -o /dev/null -w \"%{http_code}\n\" https://api.github.com/rate_limit"

  echo "== anything else is refused by the proxy, not by the guest =="
  if kelyfos exec "curl -sS -m 10 https://example.com"; then
    echo "example.com should have been refused"; exit 1
  fi

  echo "== and the credential is not in the guest =="
  if kelyfos exec "env" | grep -i token; then echo "a token reached the guest"; exit 1; fi
  if kelyfos exec "grep -rl not-a-real-token /etc /root /tmp 2>/dev/null"; then
    echo "the value is on the guest disk"; exit 1
  fi
  echo "no environment variable and no file in the guest carries the value"
'

echo
echo "== what the host wrote down =="
# The record is the host's, not the guest's. It names the secret and never
# carries its value, and it says which connections the proxy could read:
# terminated means it decrypted them to inject the credential, tunnelled means
# it relayed bytes it could not read.
kelyfos log | grep -E '^[0-9:.]+ +(secret|egress)'

kelyfos log | grep -q 'secret .*GITHUB_TOKEN -> api.github.com'
kelyfos log | grep -q 'egress allowed api.github.com:443 *mode=terminated'
kelyfos log | grep -q 'egress BLOCKED example.com:443'
kelyfos log --verify
```

---

## 3. Give the agent your files

Firecracker has no shared filesystem, so `--workspace` is a copy in and a copy
back rather than a mount: the directory is packed into an ext4 image, attached
as a second block device at `/work`, and written back on clean shutdown.

<!-- recipe: workspace -->

```bash
set -euo pipefail
root="$(mktemp -d)"
project="$root/project"
mkdir -p "$project"
trap 'rm -rf "$root"' EXIT
cd "$project"

echo 'print("hello from the sandbox")' > hello.py
echo 'notes' > NOTES.md

# `run -- <command>` ties the sandbox's lifetime to that command: it boots,
# exports KELYFOS_SANDBOX so the tools below attach to it, runs the command on
# the host, then tears down and writes the workspace back. It exits with the
# command's own status, so it composes in a script.
#
# --workspace packs the directory into an ext4 image and attaches it as a second
# block device at /work. Firecracker has no shared filesystem, so this is a copy
# in and a copy back, not a mount — which is why the agent's writes appear only
# after a clean shutdown.
kelyfos run --image dev --workspace . -- bash -c '
  set -e
  echo "== the project is inside =="
  kelyfos exec "ls /work"

  echo "== change it =="
  kelyfos exec "cd /work && python3 hello.py > output.txt"
  kelyfos exec "echo \"# edited in the sandbox\" >> /work/NOTES.md"
  kelyfos exec "cat /work/output.txt"
'

# Worth knowing before it confuses you: the write-back is a swap, not a merge.
# The old directory is renamed away and the reconstructed one is renamed into
# place, so a file the agent deleted is really gone — and a shell whose current
# directory *is* the workspace is now sitting in a directory that no longer
# exists. Step back into it by name.
cd "$project"

echo "== and the host directory has the change =="
cat output.txt
tail -1 NOTES.md
test -f output.txt || { echo "output.txt did not come back"; exit 1; }
grep -q 'edited in the sandbox' NOTES.md || { echo "the edit did not come back"; exit 1; }
echo "workspace round-trip complete"
```

---

## 4. Prepare a machine once, then fork it

A snapshot is the guest's memory and device state on disk. Restoring it three
times gives three machines that each map that memory image privately, so the
kernel provides page-level copy-on-write and the third copy costs about a page
table rather than another 512 MiB.

Each fork resumes with a corrected clock and fresh entropy. Without that they
would all draw from an identical random pool and generate the same session ids,
nonces and temporary filenames — a failure that looks like nothing at all until
two of them collide.

<!-- recipe: snapshot-and-fork -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'pkill -f "kelyfos run" 2>/dev/null || true; rm -rf "$work"' EXIT

# Prepare a machine once: install what you need, clone the repository, warm the
# caches. This stands in for whatever your expensive setup is.
kelyfos run --image dev -- bash -c '
  set -e
  kelyfos exec "mkdir -p /prepared && echo \"expensive setup output\" > /prepared/marker"
  kelyfos exec "cat /prepared/marker"

  # Freeze it. A snapshot is the guest'"'"'s memory and device state on disk.
  kelyfos snapshot save --name prepared
'

# Three copies of that prepared machine. Each maps the snapshot's memory image
# privately, so the kernel gives page-level copy-on-write for free: this costs
# about a page table rather than three times the RAM.
# `fork` holds the machines for as long as it runs, the way `run` and `team up`
# do, and unlike `run` it has no trailing-command form. Background it and wait
# for the line that says they are all live.
echo
echo "== fork =="
kelyfos fork --name prepared -n 3 --image dev >fork.log 2>&1 &
forks=$!
for _ in $(seq 1 400); do grep -q 'live in' fork.log && break; sleep 0.25; done
grep -q 'live in' fork.log || { cat fork.log; exit 1; }
cat fork.log
ids="$(awk '/^fork [0-9]+\/[0-9]+/{print $4}' fork.log)"
test "$(echo "$ids" | wc -l)" -eq 3 || { echo "expected three forks, got: $ids"; exit 1; }

echo
echo "== every fork has the prepared state, and diverges from here =="
n=0
for id in $ids; do
  n=$((n+1))
  kelyfos exec --sandbox "$id" 'cat /prepared/marker' >/dev/null
  kelyfos exec --sandbox "$id" "echo fork-$n > /prepared/who"
done
for id in $ids; do
  printf '  %s: %s\n' "$id" "$(kelyfos exec --sandbox "$id" 'cat /prepared/who')"
done

# Each fork resumes with a corrected clock and fresh entropy. Without that they
# would all draw from an identical random pool and generate the same session
# ids, nonces and temporary filenames — a failure that looks like nothing at all
# until two of them collide.
echo
echo "== and with randomness of its own =="
for id in $ids; do
  printf '  %s: %s\n' "$id" \
    "$(kelyfos exec --sandbox "$id" 'head -c 8 /dev/urandom | od -An -tx1 | tr -d " "')"
done

echo
echo "the parent snapshot is untouched, and forks are vsock-only: a fork cannot"
echo "carry a network identity, because the guest's address lives inside the"
echo "memory image every fork shares."
kill -INT $forks 2>/dev/null || true
wait $forks 2>/dev/null || true
```

---

## 5. Three agents, an ask round-trip, and a refused edge

A team is declared, not orchestrated. You write down who exists and who may talk
to whom, and `kelyfos team up` boots that graph. The part that needed an
operating system to do properly is that **no guest ever has a network path to
another guest**: every message goes through a host broker that checks it against
the edge list and records it either way, refusals included.

Your agent framework calls these tools for you. Driving them by hand takes one
helper, because MCP over stdio is newline-delimited JSON-RPC and a blocking tool
answers when the other side acts rather than when the request is written.

<!-- recipe: three-agent-team -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'kelyfos team down >/dev/null 2>&1 || true; pkill -f "kelyfos team up" 2>/dev/null || true; rm -rf "$work"' EXIT

# A team is declared, not orchestrated. You write down who exists and who may
# talk to whom; `kelyfos team up` boots that graph. No guest ever has a network
# path to another guest: every message goes through a host broker that checks it
# against this edge list and records it either way.
cat > kelyfos.toml <<'TOML'
[team]
name = "cookbook"

[[team.agent]]
name  = "master"
image = "dev"

[[team.agent]]
name  = "worker"
image = "dev"
count = 2                 # worker-1 and worker-2, neither with any network

[[team.edge]]
from = "master"
to   = "worker-*"         # a star: no worker may reach another worker

[team.store]
enabled = true
TOML

# `team up` holds the team for as long as it runs, the way `run` does — there is
# no trailing-command form for a team yet. Background it and wait for the line
# that says every agent is ready.
kelyfos team up >up.log 2>&1 &
team=$!
for _ in $(seq 1 600); do grep -q 'team up in' up.log && break; sleep 0.25; done
grep -q 'team up in' up.log || { cat up.log; exit 1; }
cat up.log
echo
kelyfos team ps

# An agent framework calls the team tools for you. Driving them by hand needs
# one helper, because MCP over stdio is newline-delimited JSON-RPC and a
# blocking tool answers when the other side acts, not when the request is sent.
sandbox() { python3 -c "
import json,sys
a=json.load(open('$HOME/.cache/kelyfos/run/team.json'))['agents']
print([x['sandbox'] for x in a if x['name']=='$1'][0])"; }

call() {  # call <agent> <tool> <args-json> [seconds to hold the channel open]
  { printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cookbook","version":"1"}}}' \
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

echo
echo "== master hands worker-1 a task =="
call master team_send '{"to":"worker-1","body":"count the files in /etc"}' 3 | text

echo "== worker-1 takes it =="
call worker-1 team_recv '{"timeout_ms":10000}' 3 | text

echo "== worker-1 asks a clarifying question and waits for the answer =="
call worker-1 team_ask '{"to":"master","body":"only regular files?","timeout_ms":30000}' 20 > ask.out &
asker=$!
sleep 3

# The question arrives at the master as an ordinary tool result, carrying the
# tag that identifies the conversation.
q="$(call master team_recv '{"timeout_ms":15000}' 3)"
echo "  master received: $(echo "$q" | text)"
correlate="$(echo "$q" | field correlate)"
call master team_reply "{\"correlate\":\"$correlate\",\"body\":\"yes, regular files only\"}" 3 | text
wait $asker
echo "  worker-1's ask returned: $(text < ask.out)"

echo "== the store is how they share results =="
call worker-1 team_store_put '{"key":"findings/worker-1","value":"41 regular files"}' 3 | text
call master team_store_get '{"key":"findings/worker-1"}' 3 | text

echo "== and an edge that was never declared is refused =="
call worker-1 team_send '{"to":"worker-2","body":"psst"}' 3 | text

echo
echo "== one team, one transcript =="
kelyfos team down
sleep 1

# A team is deliberately one session, so one chain covers every agent: the
# messages, the store accesses, the refusal, and anything any of them ran.
# With no --session, kelyfos log takes the most recent.
kelyfos log | grep -E '  team'
kelyfos log --verify
```

---

## 6. Read the record, and prove it has not been edited

Every event is written by the host and carries the hash of the one before it. A
guest that could write its own audit trail could write a flattering one, so it
cannot write one at all.

This is tamper-*evident*, not tamper-proof: anyone who can write the file can
rewrite it end to end and recompute every hash. What the chain buys is that a
*selective* edit — deleting one blocked connection, softening one command —
breaks every hash after it. That is exactly the edit somebody covering their
tracks wants to make, so the recipe makes it and watches it fail.

<!-- recipe: audit-log -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# Do a few things worth recording, including one the policy refuses.
kelyfos run --image dev --allow example.com -- bash -c '
  set -e
  kelyfos exec "echo \"a result\" > /tmp/result.txt"
  kelyfos exec "cat /tmp/result.txt"
  kelyfos exec "curl -sS -m 10 https://pypi.org" || true
'

# With no --session, every one of these takes the most recent. `kelyfos log
# --list` shows the rest.
echo
echo "== the session, replayed =="
kelyfos log | head -24

echo
echo "== the chain holds =="
kelyfos log --verify

echo
echo "== a report you can send someone, with no server behind it =="
kelyfos log --export report.html
ls -l report.html

# Tamper-evidence is a claim, so check it rather than repeat it. Every event
# carries the hash of the one before, so editing one breaks every hash after it
# — which is exactly the edit somebody covering their tracks would make.
echo
echo "== and one altered byte breaks it =="
session="$(kelyfos log --verify | sed -n 's/^session \([0-9a-f]*\):.*/\1/p')"
events="$HOME/.cache/kelyfos/sessions/$session/events.jsonl"
cp "$events" "$work/events.bak"
python3 - "$events" <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
i = next(n for n, l in enumerate(lines) if '"type":"command.start"' in l)
lines[i] = lines[i].replace("a result", "a different result", 1)
open(path, "w").write("\n".join(lines) + "\n")
PY
if kelyfos log --session "$session" --verify; then
  cp "$work/events.bak" "$events"
  echo "the chain verified after tampering, which it must never do"
  exit 1
fi
cp "$work/events.bak" "$events"
echo
echo "restored, and it verifies again:"
kelyfos log --session "$session" --verify
```

---

## 7. Drive KelyfOS from the E2B SDK

The shim serves an E2B-compatible REST subset so code already written against
their SDK can point at a self-hosted box. Sandboxes and files work; commands do
not, because the current SDK runs those over Connect RPC with protobuf rather
than REST. Use `kelyfos mcp` for commands — it is KelyfOS's actual interface and
a published standard rather than one product's internal API.

Two things a shim sandbox does **not** get, which
[`e2b-shim.md`](e2b-shim.md) states and this recipe will not pretend otherwise
about: no flight recorder, and no `kelyfos.toml` resource caps.

<!-- recipe: e2b-shim -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"

# The shim serves an E2B-compatible REST subset so code already written against
# their SDK can point at a self-hosted KelyfOS box. It is a subset on purpose:
# sandboxes and files work, commands do not, because the SDK runs those over
# Connect RPC with protobuf rather than REST. Use `kelyfos mcp` for commands.
kelyfos shim --addr 127.0.0.1:3000 --image dev >shim.log 2>&1 &
shim=$!
trap 'kill $shim 2>/dev/null; wait $shim 2>/dev/null; rm -rf "$work"' EXIT
for _ in $(seq 1 100); do
  curl -sf -o /dev/null http://127.0.0.1:3000/health && break
  sleep 0.1
done
curl -sf -o /dev/null http://127.0.0.1:3000/health || { cat shim.log; exit 1; }
echo "the shim is up"

python3 -m venv .venv
./.venv/bin/pip install --quiet e2b

# The key is never checked — the shim has no accounts and no billing — but the
# SDK validates its shape before sending it anywhere, so it has to look like one.
export E2B_API_KEY=e2b_0000000000000000000000000000000000000000
export E2B_API_URL=http://127.0.0.1:3000
export E2B_SANDBOX_URL=http://127.0.0.1:3000

./.venv/bin/python - <<'PY'
from e2b import Sandbox

sbx = Sandbox.create()
print("booted a real Firecracker microVM:", sbx.sandbox_id)

sbx.files.write("/work/hello.txt", "hello from the E2B SDK\n")
got = sbx.files.read("/work/hello.txt")
print("read it back:", got.strip())
assert got.strip() == "hello from the E2B SDK", got

sbx.kill()
print("and stopped it")
PY

echo "the E2B SDK drove a KelyfOS sandbox"
```

---

## 8. Drive a sandbox from Python, with the official MCP SDK

The MCP bridge is how an orchestrator you write reaches a guest. `kelyfos mcp`
copies bytes between its own standard streams and the sandbox's MCP server, so
any off-the-shelf MCP client talks to the guest directly: no host, no port, no
API key, because the transport is a subprocess.

This is the pattern behind
[`integrating.md`](integrating.md), and it is the one to copy if you are
building something on top of KelyfOS rather than using it from a terminal.

<!-- recipe: python-mcp-client -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

python3 -m venv .venv
./.venv/bin/pip install --quiet mcp

# The orchestrator. It boots nothing itself: `kelyfos run -- <command>` gives it
# a sandbox and sets KELYFOS_SANDBOX, and `kelyfos mcp` bridges this process's
# standard streams to that guest's MCP server. The bridge is a byte-level
# pass-through, so an off-the-shelf MCP client talks to the guest directly.
cat > orchestrator.py <<'PY'
import asyncio, os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # No host, no port, no API key: the transport is a subprocess.
    params = StdioServerParameters(command="kelyfos", args=["mcp"], env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            info = await session.initialize()
            print("connected to", info.server_info.name, info.server_info.version)

            tools = await session.list_tools()
            print("tools:", " ".join(t.name for t in tools.tools))

            out = await session.call_tool("exec", {"command": "python3 -c 'print(6*7)'"})
            print("exec said:", out.content[0].text.strip())
            assert out.structured_content["exit_code"] == 0

            await session.call_tool("write_file", {"path": "/tmp/answer.txt", "content": "42\n"})
            back = await session.call_tool("read_file", {"path": "/tmp/answer.txt"})
            print("round-tripped a file:", back.content[0].text.strip())

            # A tool that fails comes back as a tool result with isError set,
            # not as a transport error: the model is meant to see it and adapt.
            bad = await session.call_tool("exec", {"command": "exit 3"})
            print("a failing command is a result, not an exception:",
                  "isError" if bad.is_error else "no error", bad.structured_content["exit_code"])

asyncio.run(main())
PY

kelyfos run --image dev -- ./.venv/bin/python orchestrator.py

echo
echo "== and the host recorded every one of those calls =="
kelyfos log | grep -E 'via mcp|\$ ' | head -6
kelyfos log --verify
```

---

## Running them yourself

```
bash dev/cookbook.sh                    every recipe
bash dev/cookbook.sh three-agent-team   just that one
```

Each recipe starts from a clean machine, because a sandbox left behind by the
previous one makes the next one fail for a reason that has nothing to do with
it. The extractor refuses a shell block that has no `<!-- recipe: name -->`
above it: a runnable-looking block CI never runs is precisely the one that
quietly rots.
