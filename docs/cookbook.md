# KelyfOS cookbook

Fourteen recipes, each one complete, each one runnable as it stands.

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
answers when the other side acts rather than when the request is written. That
is what the trailing `sleep` in the helper is for. Close the channel first and
the bridge answers the call itself with an error saying so — better than the
silence it used to be, and still not the answer you wanted.

The `protocolVersion` the helper sends is what the *client* proposes. The guest
answers with the version it implements, which may be a later one — that is MCP
version negotiation working, not a mismatch.

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
kelyfos log | sed -n '1,24p'

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

A shim sandbox is a sandbox like any other: the project's `kelyfos.toml` caps
it, and it writes its own flight recorder — `kelyfos log --list` will show the
one this recipe creates. What the shim does not do is authenticate anybody, so
treat the port the way you would any unauthenticated local API.

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
kelyfos log | grep -E 'via mcp|\$ ' | sed -n '1,6p'
kelyfos log --verify
```

---

## 9. Point an MCP client at KelyfOS

`kelyfos serve-mcp` makes KelyfOS itself an MCP server, so a client's agent gains
`sandbox_run`, `sandbox_exec`, the file and state tools and the team tools —
without the client ever learning what a microVM is. The configuration is one
entry in a file, and between clients the shape differs only in the key name.

Two things are worth being explicit about, and both are things a client will
otherwise decide for you.

**Which policy the server is held to.** It searches upward from its working
directory for `kelyfos.toml`, and that working directory belongs to the client,
not to you: a client launched from somewhere outside the project would find no
policy and run with no ceiling at all. Name the file with `--policy`, and a path
that turns out to be wrong is an error rather than a quiet fall back to no wall.

**Which binary.** `"command": "kelyfos"` is a `PATH` lookup in an environment
the client chose, and clients do not promise you a login shell's `PATH`. Name
the binary absolutely for the same reason you name the policy absolutely. This
matters most on macOS, where there is no `kelyfos` on the host at all — KelyfOS
needs Linux with `/dev/kvm`, so the binary lives inside the VM and the entry has
to reach into it. Both shapes are below, and the repository's own `.mcp.json`
uses [`dev/mcp-server.sh`](../dev/mcp-server.sh), which picks between them.

<!-- recipe: mcp-client-config -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# The policy. This file is the wall: the server is held to it, and no tool any
# client calls can widen it.
cat > kelyfos.toml <<'TOML'
[sandbox]
image = "dev"
allow = ["api.github.com"]

[resources]
cpus = 2
mem  = "512M"

[mcp]
max_sandboxes = 2
TOML

# The binary, named rather than looked up. On Linux this is wherever you put it;
# on macOS there is nothing here to name, and the block after this one shows what
# to write instead.
bin="$(command -v kelyfos)"

# Claude Code, project scope. Checked into the repository, where it doubles as
# configuration your team gets for free. CLAUDE_PROJECT_DIR is set in the
# server's environment, and in this file it needs the ":-." default to expand.
cat > .mcp.json <<JSON
{
  "mcpServers": {
    "kelyfos": {
      "type": "stdio",
      "command": "$bin",
      "args": ["serve-mcp", "--policy", "\${CLAUDE_PROJECT_DIR:-.}/kelyfos.toml"]
    }
  }
}
JSON

# VS Code, workspace scope. The same server, a different key and a different
# variable — which is the whole of the difference.
mkdir -p .vscode
cat > .vscode/mcp.json <<JSON
{
  "servers": {
    "kelyfos": {
      "type": "stdio",
      "command": "$bin",
      "args": ["serve-mcp", "--policy", "\${workspaceFolder}/kelyfos.toml"]
    }
  }
}
JSON

echo "== on macOS the binary is inside the Lima VM, so the entry reaches into it =="
cat <<'MACOS'
   {
     "mcpServers": {
       "kelyfos": {
         "type": "stdio",
         "command": "limactl",
         "args": ["shell", "kelyfos-dev", "--",
                  "/abs/path/to/repo/bin/kelyfos", "serve-mcp",
                  "--policy", "/abs/path/to/repo/kelyfos.toml"]
       }
     }
   }
MACOS
echo "   the binary path is absolute because a non-interactive 'limactl shell' gets a"
echo "   minimal PATH; the home path is the same on both sides of the Lima mount."

echo
echo "== the same server from a command line, if you would rather not write the file =="
echo "   claude mcp add --transport stdio kelyfos -- \"$bin\" serve-mcp --policy \"\$PWD/kelyfos.toml\""

# Neither client is needed to check that the configuration is right. Read the
# entry back out of each file, expand the variable that client would expand, run
# exactly what it names, and speak MCP to it.
cat > check.py <<'CHECK'
import json, os, subprocess, sys

path, key = sys.argv[1], sys.argv[2]
entry = json.load(open(path))[key]["kelyfos"]
argv = [entry["command"]] + [
    a.replace("${CLAUDE_PROJECT_DIR:-.}", os.getcwd()).replace("${workspaceFolder}", os.getcwd())
    for a in entry["args"]
]
print("  %s -> %s" % (path, " ".join(argv)))

p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def send(m):
    p.stdin.write(json.dumps(m) + "\n")
    p.stdin.flush()

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                 "clientInfo": {"name": "cookbook", "version": "1"}}})
init = json.loads(p.stdout.readline())["result"]
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools = json.loads(p.stdout.readline())["result"]["tools"]

# Ask for four cores against a ceiling of two. Nothing boots: the refusal comes
# before anything is built, and it names the file and the line it came from.
send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
      "params": {"name": "sandbox_run", "arguments": {"cpus": 4}}})
refused = json.loads(p.stdout.readline())["result"]
p.stdin.close()
p.wait(timeout=30)

print("   server %s %s, protocol %s, %d tools"
      % (init["serverInfo"]["name"], init["serverInfo"]["version"],
         init["protocolVersion"], len(tools)))
assert "kelyfos.toml" in init["instructions"], "the agent is not told where the wall is"
assert refused["isError"], "a request above the ceiling was granted"
print("   refused:", refused["content"][0]["text"].splitlines()[0])
CHECK

echo
echo "== each configuration file, proved by running exactly what it names =="
python3 check.py .mcp.json mcpServers
python3 check.py .vscode/mcp.json servers
```

---

## 10. Drive the host from Python, with the official MCP SDK

The outward twin of recipe 8. There the SDK talked to a guest through
`kelyfos mcp`; here it talks to KelyfOS itself, and the tools it gets are the
host's: boot a machine, work in it, freeze it, fork it.

`command="kelyfos"` here is a `PATH` lookup, which is fine for a program you run
yourself on Linux and wrong under a client or on macOS — recipe 9 has both
shapes.

Everything it does is bounded by the policy file, and the last thing it does is
read the record the server kept of its own calls — including the one that was
refused, which is the half a transcript most needs and least often has.

<!-- recipe: mcp-client-host -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

cat > kelyfos.toml <<'TOML'
[sandbox]
image = "dev"

[resources]
cpus = 2
mem  = "512M"

[mcp]
max_sandboxes = 3
TOML

python3 -m venv .venv
./.venv/bin/pip install --quiet mcp

cat > agent.py <<'AGENT'
import asyncio, os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    params = StdioServerParameters(
        command="kelyfos",
        args=["serve-mcp", "--policy", os.path.join(os.getcwd(), "kelyfos.toml")],
        env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            info = await session.initialize()
            print("connected to", info.server_info.name, info.server_info.version)
            tools = await session.list_tools()
            print("tools:", " ".join(t.name for t in tools.tools))

            box = await session.call_tool("sandbox_run", {"cpus": 1})
            sid = box.structured_content["sandbox"]
            print("sandbox %s ready in %d ms" % (sid, box.structured_content["boot_ms"]))

            await session.call_tool("sandbox_write_file",
                {"sandbox": sid, "path": "/work/task.txt", "content": "the prepared state\n"})
            out = await session.call_tool("sandbox_exec",
                {"sandbox": sid, "command": "wc -c < /work/task.txt"})
            print("exec said:", out.content[0].text.strip().splitlines()[0])

            # Prepare once, fork many. Each fork resumes from the same state and
            # then diverges; the machine that was snapshotted keeps running.
            await session.call_tool("sandbox_snapshot", {"sandbox": sid, "name": "prepared"})
            forks = await session.call_tool("sandbox_fork", {"name": "prepared", "count": 2})
            ids = forks.structured_content["sandboxes"]
            print("forked into %d machines in %d ms"
                  % (len(ids), forks.structured_content["wall_ms"]))
            for f in ids:
                back = await session.call_tool("sandbox_read_file",
                    {"sandbox": f, "path": "/work/task.txt"})
                # structured_content, not the text block: a client that reads
                # only the structured form must still get the file.
                print("  %s sees: %s (%s)" % (
                    f, back.structured_content["content"].strip(),
                    back.structured_content["encoding"]))

            # Asking for more than the policy allows is a result, not an
            # exception: the refusal names the ceiling and the line it came
            # from, so an agent can act on it by asking for less.
            bad = await session.call_tool("sandbox_run", {"cpus": 64})
            assert bad.is_error
            print("refused:", bad.content[0].text.splitlines()[0])

            for f in ids + [sid]:
                await session.call_tool("sandbox_stop", {"sandbox": f})

asyncio.run(main())
AGENT

./.venv/bin/python agent.py

echo
echo "== and the server kept a record of every call it was asked for =="
session="$(kelyfos log --list | grep serve-mcp | sed -n 1p | awk '{print $1}')"
kelyfos log --session "$session" | grep -E 'client (call|result)' | sed -n '1,10p'
echo
kelyfos log --verify --session "$session"
```

---

## 11. Both directions at once, and how to write a plugin

The two MCP doors point opposite ways, and this runs them together. An outside
client drives `kelyfos serve-mcp` to make a sandbox and work in it; an agent
attached to that same sandbox through `kelyfos mcp` calls a plugin running
beside it inside the guest. Neither knows about the other, and the machine's own
record holds both.

The plugin is written out in full below, because there is nothing to it: an MCP
server is a program that reads newline-delimited JSON-RPC on standard input and
writes it on standard output. This one is twenty lines of Python and the
standard library. KelyfOS launches it from a read-only device, in the guest,
with the sandbox's own environment — so a plugin can do exactly what agent-code
in that sandbox could do, and nothing else.

Read the transcript at the end. The sandbox's chain says what was done to the
machine: the commands and file writes the outside client asked for, marked
`via: serve-mcp`, and every plugin call the inner agent made. The server's own
chain says what the client *asked for*, including the call that was refused —
which never reached a machine at all, so there is nothing about it in the
machine's record to find.

<!-- recipe: both-directions -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# A plugin is a directory with a program in it. The host packs this directory
# into a read-only device and mounts it at /plugins/demo inside the guest.
mkdir -p plugins/demo
cat > plugins/demo/server.py <<'PLUGIN'
import json, os, sys

TOOLS = [{"name": "echo", "description": "Return the text it was given, prefixed.",
          "inputSchema": {"type": "object",
                          "properties": {"text": {"type": "string"}},
                          "required": ["text"]}},
         {"name": "where", "description": "Report the plugin's directory and whether it is writable.",
          "inputSchema": {"type": "object"}}]

def answer(rid, value):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": value}) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    msg = json.loads(line)
    rid = msg.get("id")
    if rid is None:
        continue                      # a notification; JSON-RPC forbids answering one
    if msg["method"] == "initialize":
        answer(rid, {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                     "serverInfo": {"name": "demo", "version": "1.0.0"}})
    elif msg["method"] == "tools/list":
        answer(rid, {"tools": TOOLS})
    elif msg["method"] == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments") or {}
        if name == "echo":
            answer(rid, {"content": [{"type": "text", "text": "demo says: " + args["text"]}]})
        else:
            answer(rid, {"content": [{"type": "text", "text": "cwd %s, writable %s" % (
                os.getcwd(), os.access(os.getcwd(), os.W_OK))}]})
PLUGIN

cat > kelyfos.toml <<'TOML'
[sandbox]
image = "dev"

[resources]
cpus = 2
mem  = "512M"

[mcp]
max_sandboxes = 2

# The name is the prefix of every tool this plugin advertises: the agent sees
# demo_echo and demo_where. Lowercase letters, digits and dashes only, so the
# prefix can never contain the separator.
[[plugin]]
name    = "demo"
path    = "./plugins/demo"
command = "python3"
args    = ["server.py"]
TOML

cat > both.py <<'BOTH'
import json, os, subprocess, threading, queue, time


class Client:
    """One MCP client over a subprocess's standard streams."""

    def __init__(self, argv, errlog):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=open(errlog, "wb"))
        self.q, self.pend, self.nid = queue.Queue(), {}, 0
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.q.put(line)
        self.q.put(None)

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self.nid += 1
            msg["id"] = self.nid
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()
        return None if notify else self.nid

    def wait(self, i, t=180):
        end = time.time() + t
        while True:
            if i in self.pend:
                return self.pend.pop(i)
            item = self.q.get(timeout=max(1, end - time.time()))
            if item is None:
                raise SystemExit("the peer closed the stream")
            d = json.loads(item)
            if d.get("id") is not None:
                self.pend[d["id"]] = d

    def start(self, name):
        info = self.wait(self.send("initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": name, "version": "1"}}))["result"]
        self.send("notifications/initialized", notify=True)
        return info

    def tools(self):
        return [t["name"] for t in self.wait(self.send("tools/list"))["result"]["tools"]]

    def call(self, tool, args=None):
        d = self.wait(self.send("tools/call", {"name": tool, "arguments": args or {}}))
        if "error" in d:
            return True, "PROTOCOL " + d["error"]["message"], {}
        r = d["result"]
        text = r["content"][0]["text"] if r.get("content") else ""
        return r.get("isError", False), text, r.get("structuredContent") or {}

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=120)


def show(who, label, triple):
    err, text, _ = triple
    first = text.strip().splitlines()[0] if text.strip() else ""
    print("  [%-5s] %-22s isError=%-5s %s" % (who, label, err, first))


# --- outward: a client that wants a machine -------------------------------
# The policy is named, not discovered: a serve-mcp that searches upward from a
# working directory somebody else chose can find none and run with no ceiling.
outer = Client(["kelyfos", "serve-mcp", "--policy",
                os.path.join(os.getcwd(), "kelyfos.toml")], "outer.log")
print("outer server:", outer.start("outer")["serverInfo"]["name"])
_, text, sc = outer.call("sandbox_run", {"cpus": 1})
print("  [outer]", text)
box = sc["sandbox"]

show("outer", "write a file", outer.call("sandbox_write_file",
     {"sandbox": box, "path": "/work/brief.txt", "content": "look at the plugin\n"}))
show("outer", "run a command", outer.call("sandbox_exec",
     {"sandbox": box, "command": "wc -w < /work/brief.txt"}))
show("outer", "ask for more", outer.call("sandbox_run", {"cpus": 64}))

# --- inward: an agent inside that same machine ----------------------------
inner = Client(["kelyfos", "mcp", "--sandbox", box], "inner.log")
inner.start("inner")
names = inner.tools()
print("  [inner] tools:", " ".join(names))
assert "demo_echo" in names, "the plugin's tools are not in the guest's list"

show("inner", "demo_echo", inner.call("demo_echo", {"text": "from inside"}))
show("inner", "demo_where", inner.call("demo_where"))
show("inner", "read the brief", inner.call("read_file", {"path": "/work/brief.txt"}))
inner.close()

show("outer", "stop the sandbox", outer.call("sandbox_stop", {"sandbox": box}))
outer.close()

with open("ids.txt", "w") as fh:
    fh.write(box + "\n")
BOTH

python3 both.py

box="$(cat ids.txt)"
server="$(kelyfos log --list | grep serve-mcp | sed -n 1p | awk '{print $1}')"

echo
echo "== the machine's own record: what was done to it, from both directions =="
kelyfos log --session "$box" | sed -n '1,14p'
echo
echo "== the server's record: what the client asked for, refusals included =="
kelyfos log --session "$server" | grep -E 'client (call|result)' | sed -n '1,8p'
echo
kelyfos log --verify --session "$box"
kelyfos log --verify --session "$server"

kelyfos log --session "$box" --export machine.html
kelyfos log --session "$server" --export client.html
echo "exported $(wc -c < machine.html) and $(wc -c < client.html) bytes of self-contained HTML"
```

---

## 12. Stop for the day, and pick the same machine up tomorrow

A paused session is not a fresh sandbox with your files copied in. It is the
same machine: the same memory, the same processes, the same half-finished thing
in `/tmp` that no workspace would have carried.

<!-- recipe: pause-and-resume -->

```bash
set -euo pipefail

work="$(mktemp -d)"; cd "$work"
mkdir -p project && cd project
cat > kelyfos.toml <<'TOML'
[sandbox]
image = "dev"

[resources]
cpus = 2
TOML

# Boot a machine and put something into its scratch — the tmpfs overlay, which
# lives in guest RAM and belongs to no workspace. If this survives, the whole
# machine survived.
kelyfos run &
run_pid=$!
for _ in $(seq 1 60); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done

kelyfos exec "echo 'the thing I was in the middle of' > /tmp/scratch-note"
kelyfos exec "cat /tmp/scratch-note"

# Freeze it under a name. The sandbox stops; the state does not.
kelyfos pause --as before-the-migration
wait "$run_pid" 2>/dev/null || true

# It is listed, with what it costs on disk — a paused session holds your files
# inside it, so the size is in the listing rather than somewhere you have to go
# and look.
kelyfos sessions

# Change the policy while it is paused. This is the interesting case: a resumed
# machine's memory was built under the OLD policy — its proxy address, its
# environment, its open file descriptors — so that is what it runs under, and
# kelyfos says so rather than quietly using either one. Note where the key goes:
# `cpus` belongs to [resources] and `allow` does not, so the whole file is
# rewritten rather than appended to.
cat > kelyfos.toml <<'TOML'
[sandbox]
image = "dev"
allow = ["example.com"]

[resources]
cpus = 4
TOML

kelyfos resume before-the-migration &
resume_pid=$!
for _ in $(seq 1 60); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done

# The scratch file is still there. Not restored from a workspace — it was never
# in one.
kelyfos exec "cat /tmp/scratch-note"

# Stop it the way Ctrl-C would.
kill -TERM "$resume_pid" 2>/dev/null || true
wait "$resume_pid" 2>/dev/null || true

# Discard it when you are done. It says what it is about to throw away.
kelyfos sessions rm before-the-migration
echo "paused, resumed with its scratch intact, and discarded"
```

---

## 13. See what the agent changed before you keep it

An agent with a workspace writes to it. `kelyfos diff` says what it has written
so far, while it is still running; `--review` asks before any of it reaches your
directory.

<!-- recipe: review-the-diff -->

```bash
set -euo pipefail

work="$(mktemp -d)"; cd "$work"
mkdir -p ws
echo "one"   > ws/keep.txt
echo "two"   > ws/change.txt
echo "three" > ws/remove.txt

# A sandbox with the directory attached, doing what an agent would do to it.
kelyfos run --image dev --workspace ./ws -- bash -c '
  set -e
  kelyfos exec "echo added > /work/new.txt"
  kelyfos exec "echo two-changed > /work/change.txt"
  kelyfos exec "rm /work/remove.txt"
  kelyfos exec "sync"

  # From the host, while the machine is still up: what has reached the disk.
  kelyfos diff
'

# The sync-back happened, because nothing asked it not to.
cat ws/new.txt
grep -q two-changed ws/change.txt
test ! -e ws/remove.txt
echo "--- and now the same run, with --review ---"

# --review shows the same summary and waits for a yes before writing anything
# back. With nobody there to ask — a script, a CI job — it does NOT quietly sync
# and does NOT quietly skip: it routes the results beside the directory and says
# so, with a non-zero exit. A flag whose whole purpose is asking a person is a
# trap the moment it answers on their behalf.
mkdir -p ws2 && echo "original" > ws2/file.txt
set +e
kelyfos run --image dev --workspace ./ws2 --review -- \
  bash -c 'kelyfos exec "echo written-by-the-agent > /work/file.txt; sync" >/dev/null'
review_status=$?
set -e
test "$review_status" -ne 0

# The host directory is untouched...
grep -q "^original$" ws2/file.txt
# ...and the results are beside it, for you to look at.
grep -q written-by-the-agent ws2.kelyfos-out/file.txt
echo "diff showed A/M/D; --review left the directory alone and diverted the results"
```

---

## 14. Look at the web app the agent is building

`-p` carries a port on your machine to a port inside the sandbox. It does not
start anything: something in there has to be listening, and starting a
*long-running* process through `kelyfos exec` is the part worth having written
down, because the obvious spelling blocks forever.

<!-- recipe: forward-a-port -->

```bash
set -euo pipefail

work="$(mktemp -d)"; cd "$work"

# No --allow anywhere in this recipe. A forward is not a network feature: the
# transport is vsock and the supervisor dials the guest's own loopback, so this
# works on a sandbox with no network interface at all — which is most of them.
kelyfos run --image dev -p 8080:80 -- bash -c '
  set -e

  # Something to serve.
  kelyfos exec "mkdir -p /tmp/site; echo \"<h1>built in a sandbox</h1>\" > /tmp/site/index.html"

  # Start it in the background INSIDE the guest. setsid detaches it from the
  # exec channel and the redirect frees the pipes, so `kelyfos exec` returns
  # instead of waiting for a server that never exits. Without both, this call
  # hangs and the recipe never reaches the next line.
  kelyfos exec "cd /tmp/site; setsid python3 -m http.server 80 --bind 127.0.0.1 >/dev/null 2>&1 &
    sleep 1; echo started"

  # From the host, over the forward.
  curl -s http://127.0.0.1:8080/index.html

  # The listener is on loopback. Reaching it from another machine is a separate,
  # explicit decision: --p-bind 0.0.0.0, which warns every time it is used and
  # has no equivalent key in kelyfos.toml.
'

# Two things this did NOT do, and both are the point. No nftables rule was added
# — `nft list ruleset` is identical with a forward and without one — and no
# packet crossed the TAP, because the packet the server answered was created
# inside the machine, on its own loopback.
echo "reached a server inside the sandbox without touching the firewall"
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
quietly rots. It also checks that the count in the first sentence of this page
is the number of recipes on it, because that sentence is exactly the kind of
thing that goes stale the moment somebody adds one — and did.

One shell detail worth copying rather than rediscovering: these truncate output
with `sed -n '1,Np'` rather than `head -N`. Under `set -o pipefail`, `head`
exiting early sends SIGPIPE to whatever is feeding it and fails the whole
pipeline — so a recipe written with `head` passes while its output is short and
starts failing, for a reason unrelated to what it teaches, the day it is not.
