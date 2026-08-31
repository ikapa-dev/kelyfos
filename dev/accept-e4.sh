#!/usr/bin/env bash
# KelyfOS — Epic E4's acceptance test, run as the plan states it.
#
#   bash dev/accept-e4.sh
#
# Every check here is one line of E4's acceptance list (docs/roadmap.md),
# in its order, and each one either prints what it found or says why it failed.
# Nothing is asserted that is not read back out of the product.
#
# Needs a real machine: KVM, Firecracker, the dev image, and `kelyfos` on PATH.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"
WORK="$(mktemp -d)"
PASSES=0 FAILURES=0
SUMMARY=()

# This run gets its own KELYFOS_CACHE and tears down only the machines under
# it. The lines that used to be here -- a `pkill -f` on a kelyfos process name
# and `for p in $(pgrep firecracker); do kill "$p"; done` -- were host-wide
# questions answered with a kill, and on a machine running more than one
# worktree they took a peer's microVMs down with them (D79).
source "$REPO"/dev/scope.sh
scope_init accept-e4

cleanup() {
  scope_teardown
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

say "KelyfOS — Epic E4 acceptance (MCP in both directions)"
echo "  kelyfos     $(kelyfos version 2>/dev/null || echo 'not on PATH')"
echo "  arch        $(uname -m)"
echo "  work        $WORK"

cd "$WORK"
mkdir -p plugins
cp -r "$REPO/testdata/plugins/demo" plugins/

cat > kelyfos.toml <<'TOML'
[sandbox]
image = "dev"
allow = ["example.com"]

[resources]
cpus = 2
mem  = "512M"

[mcp]
max_sandboxes = 2

[[plugin]]
name    = "demo"
path    = "./plugins/demo"
command = "python3"
args    = ["server.py"]
TOML

cat > drive.py <<'DRIVE'
"""Drive both MCP doors and write what happened to facts.json."""
import json, subprocess, threading, queue, time


class Client:
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

    def call(self, tool, args=None, t=180):
        d = self.wait(self.send("tools/call", {"name": tool, "arguments": args or {}}), t)
        if "error" in d:
            return {"isError": True, "text": "PROTOCOL " + d["error"]["message"], "sc": {}}
        r = d["result"]
        return {"isError": r.get("isError", False),
                "text": r["content"][0]["text"] if r.get("content") else "",
                "sc": r.get("structuredContent") or {}}

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=120)


facts = {}
outer = Client(["kelyfos", "serve-mcp"], "outer.log")
info = outer.start("acceptance")
facts["server_name"] = info["serverInfo"]["name"]
facts["outer_tools"] = outer.tools()

# 1. boot one, and ask the guest what kernel it is running.
box = outer.call("sandbox_run", {"cpus": 1})
facts["run_error"] = box["isError"]
facts["sandbox"] = box["sc"].get("sandbox", "")
facts["uname"] = outer.call("sandbox_exec",
                            {"sandbox": facts["sandbox"], "command": "uname -a"})["text"]

# 2. a domain the project never listed.
bad = outer.call("sandbox_run", {"allow": ["evil.example.net"]})
facts["allow_refused"] = bad["isError"]
facts["allow_message"] = bad["text"]

# 3. max_sandboxes is 2: one is running, a second is fine, a third is not.
second = outer.call("sandbox_run", {"cpus": 1})
facts["second_ok"] = not second["isError"]
third = outer.call("sandbox_run", {"cpus": 1})
facts["third_refused"] = third["isError"]
facts["third_message"] = third["text"]
if facts["second_ok"]:
    outer.call("sandbox_stop", {"sandbox": second["sc"]["sandbox"]})

# 4. the plugin's tools, from inside the machine.
inner = Client(["kelyfos", "mcp", "--sandbox", facts["sandbox"]], "inner.log")
inner.start("inner")
facts["inner_tools"] = inner.tools()
echoed = inner.call("demo_echo", {"text": "acceptance"})
facts["plugin_ok"] = not echoed["isError"]
facts["plugin_said"] = echoed["text"]

# 4b. structuredContent completeness. A client is entitled to prefer
# structuredContent, and one that does — Claude Code does — sees nothing at all
# from a tool whose whole payload lives only in the text block. Checked live,
# through the host tools, because that is where it was found.
outer.call("sandbox_write_file", {"sandbox": facts["sandbox"],
                                  "path": "/tmp/structured.txt", "content": "payload\n"})
read_back = outer.call("sandbox_read_file", {"sandbox": facts["sandbox"],
                                             "path": "/tmp/structured.txt"})
facts["read_structured"] = read_back["sc"]
listed = outer.call("sandbox_list")
facts["list_structured"] = listed["sc"]

# 5. kill the plugin from outside it, the way a plugin really dies.
#
# By its command line, skipping the scanning shell itself.
#
# This used to read $d/exe, which was neater — a /proc scan matching "server.py"
# also matches the shell running the scan, since the string is in its own
# arguments. That stopped working at P5-3 and the reason is the feature: every
# process the supervisor spawns is confined by its own Landlock domain, and
# Landlock's ptrace hook refuses introspection between sibling domains. Reading
# another process's exe link needs exactly that access, so it now comes back
# empty and the scan matched nothing — while `kill` itself still works, because
# signals between siblings are not scoped. cmdline needs no such access.
kill_it = ('for d in /proc/[0-9]*; do p="${d#/proc/}"; [ "$p" = "$$" ] && continue; '
           'case "$(tr \'\\0\' \' \' < "$d/cmdline" 2>/dev/null)" in '
           '*server.py*) kill -9 "$p" ;; esac; done')
outer.call("sandbox_exec", {"sandbox": facts["sandbox"], "command": kill_it})
time.sleep(2)
after = inner.call("demo_echo", {"text": "anyone"})
facts["plugin_dead_error"] = after["isError"]
facts["plugin_dead_message"] = after["text"]
still = inner.call("exec", {"command": "echo the sandbox is untouched"})
facts["exec_after_crash"] = not still["isError"]
inner.close()

outer.call("sandbox_stop", {"sandbox": facts["sandbox"]})
outer.close()

with open("facts.json", "w") as fh:
    json.dump(facts, fh, indent=2)
DRIVE

say "driving both doors"
if ! timeout 400 python3 drive.py; then
  fail "the driver did not finish; nothing below can be trusted"
  printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
  exit 1
fi

box="$(python3 -c 'import json;print(json.load(open("facts.json"))["sandbox"])')"
server="$(kelyfos log --list | grep serve-mcp | sed -n 1p | awk '{print $1}')"

# The records are read once into files, and every check below greps the file.
#
# Not a tidiness preference: `kelyfos log | grep -q` has grep exiting on its
# first match, which SIGPIPEs the log, which under `pipefail` makes the whole
# pipeline fail — so a check can report "no" for a line that is present, and
# does so more often the longer the record gets. It cost one confusing failure
# here, and it is the same defect the cookbook recipes had.
kelyfos log --session "$box" > machine.log 2>/dev/null
kelyfos log --session "$server" > server.log 2>/dev/null
fact() { python3 -c "import json;v=json.load(open('facts.json'))['$1'];print(v if isinstance(v,str) else json.dumps(v,indent=1))"; }

say "1. a scripted client lists tools, boots a sandbox, and runs a command"
echo "     tools:  $(fact outer_tools)"
echo "     uname:  $(fact uname | sed -n '1,1p')"
check "$([ "$(fact run_error)" = "false" ] && echo yes || echo no)" "sandbox_run succeeded"
check "$(fact uname | grep -q Linux && echo yes || echo no)" "sandbox_exec returned the guest kernel string"

say "2. a domain outside the project toml is refused, and audited"
echo "     $(fact allow_message | sed -n '1,1p')"
check "$([ "$(fact allow_refused)" = "true" ] && echo yes || echo no)" "the request was refused"
# The wording moved to the catalog at E5-4 and this check was not updated with
# it, so it has been failing since — found by P5-3's regression sweep, which is
# the first time this suite had been run since. Matching the catalog's own text
# rather than a paraphrase of it.
check "$(fact allow_message | grep -q 'may never widen it' && echo yes || echo no)" "the refusal says the rule"
check "$(grep -q 'client result  sandbox_run refused' server.log && echo yes || echo no)" \
      "the refusal is an mcp.host.* audit event"

say "3. max_sandboxes + 1 is refused, and audited"
echo "     $(fact third_message | sed -n '1,1p')"
check "$([ "$(fact second_ok)" = "true" ] && echo yes || echo no)" "the second sandbox was allowed"
check "$([ "$(fact third_refused)" = "true" ] && echo yes || echo no)" "the third was refused"
check "$(fact third_message | grep -q max_sandboxes && echo yes || echo no)" "the refusal names the limit"

say "4. the demo plugin's tools are namespaced, callable, and named in the audit"
echo "     inner tools: $(fact inner_tools)"
echo "     $(fact plugin_said)"
check "$(fact inner_tools | grep -q demo_echo && echo yes || echo no)" "demo_echo is advertised"
check "$([ "$(fact plugin_ok)" = "true" ] && echo yes || echo no)" "calling it succeeded"
check "$(grep -q 'plugin call    demo_echo' machine.log && echo yes || echo no)" \
      "the audit event names the plugin"

say "4b. every tool that returns data returns it in structuredContent"
echo "     read_file: $(fact read_structured)"
check "$(fact read_structured | grep -q '"content": "payload' && echo yes || echo no)" \
      "sandbox_read_file's payload is in structuredContent, not only in the text"
check "$(fact read_structured | grep -q '"encoding": "utf-8"' && echo yes || echo no)" \
      "and it says how it encoded it"
check "$(fact list_structured | grep -q '"sandbox"' && echo yes || echo no)" \
      "sandbox_list's rows are in structuredContent"

say "5. killing the plugin costs its tools and nothing else"
echo "     $(fact plugin_dead_message | sed -n '1,1p')"
check "$([ "$(fact plugin_dead_error)" = "true" ] && echo yes || echo no)" "its tools now fail"
check "$(fact plugin_dead_message | grep -q 'no longer running' && echo yes || echo no)" \
      "the error says the plugin is gone"
check "$(grep -q 'plugin stopped demo' machine.log && echo yes || echo no)" \
      "plugin.crash is in the record"
check "$([ "$(fact exec_after_crash)" = "true" ] && echo yes || echo no)" "exec still works"

say "6. the chains verify and the export renders both lanes"
kelyfos log --verify --session "$box"
kelyfos log --verify --session "$server"
check "$(kelyfos log --verify --session "$box" >/dev/null 2>&1 && echo yes || echo no)" "the machine's chain verifies"
check "$(kelyfos log --verify --session "$server" >/dev/null 2>&1 && echo yes || echo no)" "the server's chain verifies"
kelyfos log --session "$server" --export client.html >/dev/null
kelyfos log --session "$box" --export machine.html >/dev/null
check "$(grep -q 'client called sandbox_run' client.html && echo yes || echo no)" "the export renders the client lane"
check "$(grep -q 'demo_echo' machine.html && echo yes || echo no)" "the export renders the plugin calls"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
