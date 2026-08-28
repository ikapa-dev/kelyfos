# KelyfOS cookbook

Twenty recipes, each one complete, each one runnable as it stands.

These are not illustrations. `bash dev/cookbook.sh` extracts every script below
and runs it on a real machine. Every commit checks that each recipe still
extracts and is still valid shell; actually running them needs KVM, Firecracker
and the `dev` image, so that happens in a workflow of its own — every Tuesday on
a schedule, and on demand — rather than on every push. A recipe cannot rot for
longer than seven days without saying so (F-D4, E3-3). What you copy is what was
executed.

**Before any of them.** You need Linux with `/dev/kvm`, Firecracker, the
`kelyfos` binary on your `PATH`, and the `dev` image. The
[quickstart](../README.md#quickstart) installs all of it, and `kelyfos doctor`
will tell you which piece you still owe it — every piece except the binary
itself, which `dev/install-kelyfos.sh` puts in `<repo>/bin/kelyfos` rather than
anywhere on your `PATH`.

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
# The old directory is renamed to <dir>.kelyfos-previous and the reconstructed
# one is renamed into place, so a file the agent deleted is really gone from the
# workspace — the previous copy keeps it, beside the project, until the next
# run that replaces the directory clears it — and a shell whose current
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
  kelyfos exec "mkdir -p /tmp/prepared && echo \"expensive setup output\" > /tmp/prepared/marker"
  kelyfos exec "cat /tmp/prepared/marker"

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
  kelyfos exec --sandbox "$id" 'cat /tmp/prepared/marker' >/dev/null
  kelyfos exec --sandbox "$id" "echo fork-$n > /tmp/prepared/who"
done
for id in $ids; do
  printf '  %s: %s\n' "$id" "$(kelyfos exec --sandbox "$id" 'cat /tmp/prepared/who')"
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
to   = "worker-*"         # a star: no worker may reach another worker.
                          # An edge is bidirectional unless you write
                          # `bidirectional = false`, so this is master↔worker —
                          # which is what lets worker-1 ask the master below.

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

## 6. Read the record, prove nothing in it was edited, and send it to somebody who can check it too

Every event is written by the host and carries the hash of the one before it. A
guest that could write its own audit trail could write a flattering one, so it
cannot write one at all.

This is tamper-*evident*, not tamper-proof: anyone who can write the file can
rewrite it end to end and recompute every hash. What the chain buys is that a
*selective* edit — deleting one blocked connection, softening one command —
breaks every hash after it. That is exactly the edit somebody covering their
tracks wants to make, so the recipe makes it and watches it fail.

One edit it does **not** catch, said here rather than discovered: cutting the
record short at its *end*. Nothing after the cut exists to break, so a truncated
chain verifies and reads as a session that is still open. The chain head is what
distinguishes them, and only when compared against a head from somewhere else.

The export carries the record it was rendered from, so the person you send it to
does not have to take the page's word for anything: `kelyfos verify` reads the
record back out of the file and re-runs the chain over it. Offline, no key, no
network, nothing of ours to trust. What that checks is the record and not the
page's rendering of it — `--replay` prints the record's own account, which is
how the two get compared.

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

# The report carries the record it was rendered from, so the recipient checks it
# rather than believing the page. That is the whole point of the export: no
# server, no key, no network, and nothing on their machine has to have run.
echo
echo "== and the recipient checks it themselves =="
kelyfos verify report.html

# Even without kelyfos. The report prints this line itself, and what comes out is
# the record the sender has on disk, byte for byte.
echo
echo "== the record comes back out with two lines of shell =="
sed -n '/<pre id="kelyfos-chain">/,/<\/pre>/p' report.html | sed '1d;$d' | base64 -d > extracted.jsonl
session="$(kelyfos log --verify | sed -n 's/^session \([0-9a-f]*\):.*/\1/p')"
cmp extracted.jsonl "$HOME/.cache/kelyfos/sessions/$session/events.jsonl"
echo "byte-identical to the flight recorder"

# With kelyfos, the same thing and a check in one command. The record goes to
# stdout and the verdict to stderr, so the redirect captures the record and
# nothing else.
kelyfos verify --json report.html > piped.jsonl
cmp piped.jsonl "$HOME/.cache/kelyfos/sessions/$session/events.jsonl"
echo "and the same through kelyfos verify --json"

# Editing the page's timeline and leaving the record alone is the one thing
# verification cannot catch, so the product says so rather than implying
# otherwise — and the reader is given a way to see the disagreement themselves.
echo
echo "== editing the page's timeline does not change the record it carries =="
sed 's/a result/a different result/g' report.html > doctored.html
kelyfos verify doctored.html
kelyfos verify --replay doctored.html | grep -q "a result"
echo "the record still says what it always said"

# The numbers the page states about the record are a different matter: those are
# checked, because the chain head is the one value a reader is told to compare
# against a head they were given somewhere else.
echo
echo "== but a page that lies about its own chain head is caught =="
head="$(kelyfos verify report.html | sed -n 's/.*chain head //p')"
sed "s/$head/$(printf '9%.0s' $(seq 64))/" report.html > lying.html
if kelyfos verify lying.html; then
  echo "a page stating the wrong head verified, which it must never do"
  exit 1
fi
echo "refused, as it must be"

# And a report can say who exported it. The key is yours — this product does not
# mint one, because a signature is worth exactly what knowing the key is worth.
if command -v openssl >/dev/null; then
  echo
  echo "== signed by a key you hold =="
  openssl genpkey -algorithm ed25519 -out signing.key 2>/dev/null
  openssl pkey -in signing.key -pubout -out signing.pub 2>/dev/null
  kelyfos log --export signed.html --sign-key signing.key

  # Checked against the key the reader already has, which is the only version of
  # the question worth asking: the key inside the file proves only that whoever
  # made the file had one.
  kelyfos verify signed.html --key signing.pub | grep -q "signed by the key you named"
  echo "the signature checks against the key held separately"

  # A different key is a mismatch, not a footnote.
  openssl genpkey -algorithm ed25519 -out other.key 2>/dev/null
  openssl pkey -in other.key -pubout -out other.pub 2>/dev/null
  if kelyfos verify signed.html --key other.pub; then
    echo "a report verified against a key that did not sign it"
    exit 1
  fi
  echo "and refuses a key that did not sign it"

  # An unsigned report is still a report: the signature is optional by
  # construction and never becomes required by accident.
  kelyfos verify report.html | grep -q "not signed, which is not a fault"
  echo "an unsigned report still verifies"
else
  echo "(openssl absent; skipping the signing half)"
fi

# But editing the record inside the page is caught, exactly the way editing the
# flight recorder is.
echo
echo "== editing the record inside the page is caught =="
python3 - report.html tampered.html <<'EDIT'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
i = s.index('<pre id="kelyfos-chain">') + len('<pre id="kelyfos-chain">') + 40
s = s[:i] + ("B" if s[i] != "B" else "C") + s[i+1:]
open(dst, "w").write(s)
EDIT
if kelyfos verify tampered.html; then
  echo "a tampered report verified, which it must never do"
  exit 1
fi
echo "refused, as it must be"

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
one this recipe creates. By default the shim authenticates nobody, so treat the
port the way you would any unauthenticated local API. Start it with
`KELYFOS_SHIM_TOKEN` set and every route requires a matching
`Authorization: Bearer <token>`, compared in constant time, and answers `401`
without one.

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
matters most on macOS, where the host binary refuses `serve-mcp` — the macOS
build runs `doctor`, `verify`, `version` and `help`, and nothing that needs a
guest, because Firecracker needs Linux with `/dev/kvm`. The binary that can
serve lives inside the Lima VM, so the entry has to reach into it. Both shapes
are below, and the repository's own `.mcp.json` uses
[`dev/mcp-server.sh`](../dev/mcp-server.sh), which picks between them.

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
# on macOS the binary on the host refuses serve-mcp, and the block after this one
# shows what to write instead.
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
# Both assertions have to distinguish "a policy is in force" from "there is no
# policy at all", and the obvious spellings do not. The no-policy instructions
# also mention kelyfos.toml — they say none was found — so testing for that
# string passes against a server with no ceiling whatsoever, which is the one
# thing this check exists to catch (F-D44).
assert "No kelyfos.toml was found" not in init["instructions"], \
    "this server started outside the project and has NO ceiling at all"
assert "No tool here can change it" in init["instructions"], \
    "the agent is not told the wall is fixed"
assert refused["isError"], "a request above the ceiling was granted"
assert "ceiling" in refused["content"][0]["text"], \
    "the request failed, but not because a ceiling refused it"
print("   refused:", refused["content"][0]["text"].splitlines()[0])
CHECK

echo
echo "== each configuration file, proved by running exactly what it names =="
python3 check.py .mcp.json mcpServers
python3 check.py .vscode/mcp.json servers
```

---

## 9b. Attach a client with one command

Recipe 9 shows the configuration by hand, which is what a person needs when
their client is not one of the six this command writes. This is the other way.

`kelyfos connect <client>` writes the client's own file, in its own format and
its own location. Two things it gets right that a copied snippet gets right by
luck: the policy path is **absolute**, because a server that has to find its own
policy can find none and run with no ceiling at all, and the surface is
`serve-mcp` rather than `mcp` — the first is KelyfOS as a server, the second
bridges one sandbox's guest.

`--check` then starts the server the file names and completes a real MCP
handshake, because "configured" asserted without evidence is what this command
exists to replace.

<!-- recipe: connect-a-client -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# A project with a policy. A server with no ceiling is not worth attaching, and
# `connect` refuses rather than writing a path to nothing.
mkdir -p project && cd project
cat > kelyfos.toml <<'TOML'
[resources]
cpus = 2
mem = "512M"
TOML

# The clients it knows, each with the version it was verified against.
kelyfos connect --list

# Write one. The file is the client's own.
kelyfos connect claude-code
cat .mcp.json

# Absolute, both of them.
grep -q "$(pwd)/kelyfos.toml" .mcp.json
grep -q serve-mcp .mcp.json
echo "the policy is named absolutely, and the surface is serve-mcp"

# It is a guest in somebody else's file: another server, and a key it has never
# heard of, both survive.
python3 - <<'PY'
import json
d = json.load(open(".mcp.json"))
d["mcpServers"]["somebody-elses"] = {"command": "other"}
d["aKeyWeDoNotKnowAbout"] = True
json.dump(d, open(".mcp.json", "w"), indent=2)
PY
kelyfos connect claude-code >/dev/null
python3 - <<'PY'
import json, sys
d = json.load(open(".mcp.json"))
assert "somebody-elses" in d["mcpServers"], "another server was dropped"
assert d.get("aKeyWeDoNotKnowAbout"), "an unrelated key was dropped"
assert "kelyfos" in d["mcpServers"], "kelyfos is missing"
print("another server and an unknown key both survived")
PY

# Idempotent: a second run changes nothing.
cp .mcp.json first.json
kelyfos connect claude-code >/dev/null
cmp first.json .mcp.json
echo "a second run is byte-identical"

# And the check is a real handshake against the server the file names.
kelyfos connect claude-code --check 2>&1 | grep -q "speaks MCP"
echo "the server the configuration names started and spoke MCP"

# --remove takes out exactly one entry.
kelyfos connect claude-code --remove
python3 - <<'PY'
import json
d = json.load(open(".mcp.json"))
assert "kelyfos" not in d["mcpServers"], "kelyfos survived --remove"
assert "somebody-elses" in d["mcpServers"], "--remove took another server with it"
print("removed, and nothing else went with it")
PY

# For anything the six writers do not cover, the snippet to paste:
kelyfos connect generic | sed -n '1,20p'
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

## 15. See a team's topology before booting it, and confirm the running team draws the same one

`kelyfos team graph` reads `kelyfos.toml` and draws the team it declares —
agents, edges, domains, secrets and store rules — with **nothing booted**: a
pre-flight lint, not a monitor. It runs the same plan-time checks
`kelyfos team up` runs before it boots anything, so a file that combines
`[team]` with `[[plugin]]` or `[[forward]]` is refused here too, before it
costs anybody an afternoon. `kelyfos team ps --graph` draws the identical
picture for a team that is actually running, read from its own recorded
`team.topology` and `session.policy` events rather than from the file — the
two are never independent readings of one topology.

<!-- recipe: team-graph -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'kelyfos team down >/dev/null 2>&1 || true; pkill -f "kelyfos team up" 2>/dev/null || true; rm -rf "$work"' EXIT

cat > kelyfos.toml <<'TOML'
[team]
name = "cookbook-graph"

[[team.agent]]
name  = "master"
image = "dev"
allow = ["example.com"]

[[team.agent]]
name  = "worker"
image = "dev"
count = 2

[[team.edge]]
from = "master"
to   = "worker-*"

[team.store]
enabled = true

[[team.store.key]]
name  = "findings"
write = ["worker-*"]
read  = ["master"]
TOML

echo "== declared, nothing booted =="
declared="$(kelyfos team graph)"
echo "$declared"

echo
echo "== the same file, refused, when it also carries [[plugin]] =="
mkdir -p plugins/demo
cat kelyfos.toml > refused.toml
cat >> refused.toml <<'TOML'

[[plugin]]
name    = "demo"
path    = "./plugins/demo"
command = "python3"
args    = ["server.py"]
TOML
# The refusal is expected, so its non-zero status must not abort this script
# under set -e: captured into a variable first (the left side of an && list
# is exempt), then the message is checked as its own, separate, successful
# pipeline.
refusal="$(kelyfos team graph --policy refused.toml 2>&1)" && { echo "expected a refusal, got:"; echo "$refusal"; exit 1; }
echo "$refusal" | grep -q '\[\[plugin\]\] has no effect inside a team'

echo
echo "== boot it, and confirm the running team draws the same topology =="
kelyfos team up >up.log 2>&1 &
for _ in $(seq 1 600); do grep -q 'team up in' up.log && break; sleep 0.25; done
grep -q 'team up in' up.log || { cat up.log; exit 1; }

running="$(kelyfos team ps --graph)"
echo "$running"

# The title line differs (one says "nothing booted", the other says how many
# agents came up), and a running team's legend may carry "(fork group ...)"
# on a forked agent — knowable only once something has actually booted, never
# from the file alone. Strip both and everything else has to agree exactly.
norm() { echo "$1" | tail -n +2 | sed -E 's/ \(fork group [0-9a-f]+\)//'; }
diff <(norm "$declared") <(norm "$running")
echo "declared and running topologies match"

kelyfos team down
```

---

## 16. Keep the record, erase what it said

A retention floor and a deletion request pull in opposite directions on the
same file until the record separates two claims: that a session happened,
and what it said while it did. `kelyfos sessions prune` deletes whole
sessions once they are older than the floor — never one still inside it.
`kelyfos sessions erase` answers the other half: it does not delete
anything, it rewrites a session's own content fields to a fingerprint of
what they were, in place, and the chain still verifies afterward.

<!-- recipe: retention-and-erasure -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# A session with something worth erasing: real command output.
kelyfos run --image dev -- bash -c '
  set -e
  kelyfos exec "echo my-email-is-jane@example.com > /tmp/note.txt"
  kelyfos exec "cat /tmp/note.txt"
'

session="$(kelyfos log --verify | sed -n 's/^session \([0-9a-f]*\):.*/\1/p')"
record="$HOME/.cache/kelyfos/sessions/$session/events.jsonl"

# The retention floor protects a session this fresh: -dry-run finds nothing
# eligible, because prune's own floor is 180 days by default (D61 — six
# months, the EU AI Act's own floor for a general-purpose system) and this
# one is seconds old.
echo
echo "== prune leaves a fresh session alone =="
kelyfos sessions prune -dry-run

echo
echo "== before erasure, the record holds the value =="
grep -c 'jane@example.com' "$record"

# GDPR Article 17 in one command: the content goes. The shape of what
# happened, and the fact that this ran, does not.
echo
echo "== erase it =="
kelyfos sessions erase -reason "cookbook demo — GDPR Article 17" "$session"

echo
echo "== the value is unrecoverable from the raw file =="
if grep -q 'jane@example.com' "$record"; then
  echo "the erased value is still in the file, which must never happen"
  exit 1
fi
echo "not found, as it must be"

# What erase wrote is a replacement record, not a broken one: the whole
# chain was rehashed from the first event, and it verifies end to end.
echo
echo "== the chain still verifies =="
kelyfos verify "$record"

# A fingerprint in place of the content, and the erasure itself recorded —
# an erasure that could not itself be audited would undercut the reason
# this record exists at all.
echo
echo "== what took its place =="
grep -o '"data":"[^"]*"' "$record" | tail -1
grep -o '"type":"session.erasure"[^}]*}' "$record"
```

---

## 17. Pipe a team's roster, its topology and its digest as JSON

`kelyfos team ps`, `kelyfos team graph` and `kelyfos watch` all gain `--json`
(P7-10): the extensibility surface for a view this phase did not think of,
and cheaper than a plugin system. `kelyfos team ps --json` returns the same
shape the `team_ps` MCP tool has always returned as `structuredContent`.
`kelyfos team graph --json` and `kelyfos team ps --graph --json` return the
resolved topology — agents, edges, resources, access and the indirect-reach
pairs the picture in recipe 15 draws — as data instead of a drawing.
`kelyfos watch --json` prints one snapshot of the digest — every counter, the
policy and topology events verbatim — and exits, instead of opening the live
view. `docs/teams.md` §8.5 documents every field.

<!-- recipe: team-json -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'kelyfos team down >/dev/null 2>&1 || true; pkill -f "kelyfos team up" 2>/dev/null || true; rm -rf "$work"' EXIT

cat > kelyfos.toml <<'TOML'
[team]
name = "cookbook-json"

[[team.agent]]
name  = "master"
image = "dev"
allow = ["example.com"]

[[team.agent]]
name  = "worker"
image = "dev"
count = 2

[[team.edge]]
from = "master"
to   = "worker-*"

[team.store]
enabled = true

[[team.store.key]]
name  = "findings"
write = ["worker-*"]
read  = ["master"]
TOML

echo "== declared topology, nothing booted =="
kelyfos team graph --json > declared.json
python3 -c "
import json
d = json.load(open('declared.json'))
assert d['mode'] == 'declared', d
assert d['team'] == 'cookbook-json', d
assert len(d['agents']) == 3, d['agents']
assert any(e['from'] == 'master' for e in d['edges']), d['edges']
assert any(r['kind'] == 'store_key' for r in d['resources']), d['resources']
assert d['egress_ports'] == [80, 443], d['egress_ports']
print('declared.json: mode=declared, %d agents, %d edges, %d resources' %
      (len(d['agents']), len(d['edges']), len(d['resources'])))
"

echo
echo "== boot it =="
kelyfos team up >up.log 2>&1 &
for _ in $(seq 1 600); do grep -q 'team up in' up.log && break; sleep 0.25; done
grep -q 'team up in' up.log || { cat up.log; exit 1; }

echo
echo "== kelyfos team ps --json — the same shape the team_ps MCP tool returns =="
kelyfos team ps --json > ps.json
python3 -c "
import json
d = json.load(open('ps.json'))
assert d['team'] == 'cookbook-json', d
names = sorted(a['agent'] for a in d['agents'])
assert names == ['master', 'worker-1', 'worker-2'], names
assert all(a['alive'] for a in d['agents']), d['agents']
print('ps.json: %d agents, all alive' % len(d['agents']))
"

echo
echo "== kelyfos team ps --graph --json — the running topology, as data =="
kelyfos team ps --graph --json > running.json
python3 -c "
import json
d = json.load(open('running.json'))
assert d['mode'] == 'running', d
assert d['team'] == 'cookbook-json', d
assert len(d['agents']) == 3, d['agents']
print('running.json: mode=running, %d agents, %d indirect reach pair(s)' %
      (len(d['agents']), len(d.get('indirect_reach') or [])))
"

echo
echo "== declared and running agree on agents, edges and resources =="
python3 -c "
import json
a = json.load(open('declared.json'))
b = json.load(open('running.json'))
norm = lambda d: (sorted(x['id'] for x in d['agents']),
                   sorted((e['from'], e['to']) for e in d['edges']),
                   sorted(x['id'] for x in d['resources']))
assert norm(a) == norm(b), (norm(a), norm(b))
print('agents, edges and resources match between declared and running')
"

echo
echo "== kelyfos watch --json — a one-shot snapshot of the digest, not the live view =="
kelyfos watch --json > digest.json
python3 -c "
import json
d = json.load(open('digest.json'))
assert d['team'] is True, d
assert d['events'] > 0, d
assert d['topology'] is not None, 'no team.topology in the digest'
assert any(a.get('policy') for a in d['agents']), 'no agent carries its session.policy'
print('digest.json: team=%s, %d events, topology present, %d agent(s) with a policy' %
      (d['team'], d['events'], sum(1 for a in d['agents'] if a.get('policy'))))
"

kelyfos team down
```

---

## 18. Export the record as OTLP, for tools that already speak it

`kelyfos log --export-otlp` maps the same session's chain to OTLP-JSON spans
— the shape a Jaeger, a Grafana Tempo, or an OpenTelemetry Collector's file
receiver already reads, with `invoke_agent` per agent, `execute_tool` per
command, and every egress attempt or refusal riding along as a span event.

It is a one-way projection, not a second record. `docs/otlp.md` is why: the
GenAI semantic conventions this mapping targets are still marked
"Development" with no stabilisation timeline, so this file is versioned
apart from the flight recorder and `kelyfos verify` never reads it back —
only `kelyfos log --export` (recipe 6) produces something a recipient
verifies.

<!-- recipe: otlp-export -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

kelyfos run --image dev --allow api.github.com -- bash -c '
  set -e
  kelyfos exec "echo hello > /tmp/hi.txt"
  kelyfos exec "curl -s -o /dev/null -w \"%{http_code}\n\" https://api.github.com/rate_limit"
  if kelyfos exec "curl -sS -m 10 https://example.com"; then
    echo "example.com should have been refused"; exit 1
  fi
'

echo
echo "== export the chain as OTLP-JSON =="
kelyfos log --export-otlp trace.json
ls -l trace.json

echo
echo "== span names and shape, checked straight out of the file =="
python3 - trace.json <<'PY'
import json, sys

doc = json.load(open(sys.argv[1]))
spans = [s for rs in doc["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]
names = sorted(s["name"] for s in spans)
print("\n".join(names))

assert any(n == "invoke_agent" for n in names), "no invoke_agent span"
assert any(n.startswith("execute_tool") for n in names), "no execute_tool span"

for s in spans:
    assert len(s["traceId"]) == 32, s["traceId"]
    assert len(s["spanId"]) == 16, s["spanId"]
    # OTLP/JSON's own deviation from generic protobuf-JSON: enums are
    # integers, never the enum's name string, and every 64-bit value
    # (the two timestamps) is a decimal string.
    assert isinstance(s["kind"], int) and not isinstance(s["kind"], bool)
    assert isinstance(s["startTimeUnixNano"], str)
    assert isinstance(s["endTimeUnixNano"], str)

agent = next(s for s in spans if s["name"] == "invoke_agent")
events = [e["name"] for e in agent.get("events", [])]
assert "kelyfos.egress.attempt" in events, events
assert "kelyfos.egress.refused" in events, events
print("span names and OTLP-JSON shape check out")
PY

# One-way: the flight recorder itself is unaffected by the export, and
# `kelyfos verify`/`kelyfos log --verify` never read the OTLP file — they
# read the chain, exactly as they did before this recipe ran.
echo
echo "== the flight recorder is untouched, and still verifies =="
kelyfos log --verify
```

---

## 19. Follow a running team from a file, with no server behind it

`kelyfos log --export` has never needed a session to be finished — it renders
whatever the flight recorder holds right now, a still-running team included,
and the page says "still running" rather than inventing an ending. `--refresh`
is what turns that into something worth leaving open in a tab: it rewrites
the same file atomically, on a timer, for as long as the session keeps going,
and the page it writes carries a `<meta http-equiv="refresh">` — the one
mechanism that makes an already-open browser tab reload itself and pick up
what the last rewrite wrote. There is still no server and no socket anywhere
in that path: the browser is polling a local file, and the only thing on a
clock is this one CLI process rewriting it. It stops on its own once the
session ends, or on Ctrl-C.

<!-- recipe: live-export-refresh -->

```bash
set -euo pipefail
work="$(mktemp -d)"
cd "$work"
REFRESH_PID=""
trap '[ -n "$REFRESH_PID" ] && kill "$REFRESH_PID" 2>/dev/null; kelyfos team down >/dev/null 2>&1 || true; pkill -f "kelyfos team up" 2>/dev/null || true; rm -rf "$work"' EXIT

cat > kelyfos.toml <<'TOML'
[team]
name = "cookbook-live"

[[team.agent]]
name  = "master"
image = "dev"

[[team.agent]]
name  = "worker"
image = "dev"
count = 2                 # worker-1 and worker-2, with no edge to each other

[[team.edge]]
from = "master"
to   = "worker-*"
TOML

kelyfos team up >up.log 2>&1 &
for _ in $(seq 1 600); do grep -q 'team up in' up.log && break; sleep 0.25; done
grep -q 'team up in' up.log || { cat up.log; exit 1; }

echo
echo "== --export against the team while it is still running, not a finished one =="
kelyfos log --export live.html
grep -q 'still running' live.html
echo "the export says so, because it is"

echo
echo "== --refresh: the same file, rewritten atomically as the team keeps going =="
kelyfos log --export watch.html --refresh --refresh-every 1s >refresh.log 2>&1 &
REFRESH_PID=$!
for _ in $(seq 1 120); do [ -s watch.html ] && grep -q 'meta http-equiv="refresh"' watch.html && break; sleep 0.25; done
grep -q 'meta http-equiv="refresh"' watch.html
echo "the exported page carries the tag that makes an open tab follow it"

# Checked, not assumed: every fd the --refresh process holds, none a socket.
# The property this recipe exists to prove — a browser polling a local file
# needs nothing on the write side either.
echo
echo "== no socket anywhere in that path =="
sockets="$(find "/proc/$REFRESH_PID/fd" -lname 'socket:*' 2>/dev/null | wc -l || true)"
echo "open socket fds held by the --refresh process: $sockets"
[ "$sockets" -eq 0 ]
echo "zero, as D60/D63 require of everything outside kelyfos view (P7-12)"

# Driving the team by hand needs one helper — see recipe 5 for why.
sandbox() { python3 -c "
import json
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

echo
echo "== a real change to the team's state: worker-1 messages an edge that was never declared =="
call worker-1 team_send '{"to":"worker-2","body":"psst"}' 3 | text

echo
echo "== and the open file picks it up on its own — nobody re-ran the export =="
for _ in $(seq 1 60); do grep -q 'no_edge' watch.html && break; sleep 1; done
grep -q 'no_edge' watch.html
echo "watch.html now carries the refusal, written by the loop already running"

kill "$REFRESH_PID" 2>/dev/null || true
wait "$REFRESH_PID" 2>/dev/null || true
REFRESH_PID=""
grep -q '^stopped$' refresh.log
echo "the loop stopped cleanly on its own signal"

kelyfos team down
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

One shell detail worth copying rather than rediscovering: wherever the pipeline
runs on the host, these truncate output with `sed -n '1,Np'` rather than
`head -N`. Under `set -o pipefail`, `head` exiting early sends SIGPIPE to
whatever is feeding it and fails the whole pipeline — so a recipe written with
`head` passes while its output is short and starts failing, for a reason
unrelated to what it teaches, the day it is not.

It is not a hypothetical. `dev/install-build-deps.sh` ran `make --version |
head -1` for years and failed a CI build during the v0.8 release with
`make: write error: stdout` — because `make --version` prints four lines, `head`
closed the pipe after the first, and the exit status of a dependency install
became a race. That line is now `make --version | sed -n '1,1p'`.
