package report

// reportHTML is the whole report: one file, no scripts, no external requests.
// A compliance artefact that needs a CDN to render is not one.
const reportHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KelyfOS session {{.SessionID}}</title>
<style>
.cards .l .qual{opacity:.62;font-weight:400}
  :root{
    --bg:#10161d; --panel:#161e28; --line:#26313f; --text:#c9d4de; --muted:#71818f;
    --amber:#f0a63c; --ok:#58c470; --warn:#d96a5f;
    /* The outward client's own lane: what an outside agent asked for, which is
       a different kind of fact from what happened inside a machine (E4-4). */
    --client:#7fb3d5;
    --mono:ui-monospace,"SF Mono","Cascadia Code",Consolas,monospace;
    --sans:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--sans)}
  .wrap{max-width:940px;margin:0 auto;padding:40px 20px 80px}
  body.team .wrap{max-width:1300px}
  h1{font:700 28px/1.2 var(--mono);margin:0;color:#e8eef4}
  h1 span{color:var(--amber)}
  .sub{color:var(--muted);font:13px/1.7 var(--mono);margin-top:8px}
  /* Deliberately not a badge. The green tick this replaced was the file's own
     verdict on itself, which is the one thing a reader must not take from it —
     so what sits here now is a statement of what the file carries, in the same
     colour as everything else, ending in the command somebody else runs. */
  .chain{margin-top:14px;padding:10px 14px;border-radius:4px;background:var(--panel);
         border:1px solid var(--line);font:13px/1.65 var(--mono);max-width:840px}
  .chain code{color:var(--amber);word-break:break-all}
  .chain .limit{display:block;margin-top:8px;color:var(--muted)}
  .chain .signed{display:block;margin-top:8px}
  .chain.bad{background:rgba(217,106,95,.12);color:var(--warn);border-color:rgba(217,106,95,.45)}
  .chain.bad code{color:var(--warn)}
  /* The island. Closed by default because it is evidence rather than reading,
     and open in two clicks because a reader who wants to see it should not need
     a developer console to. */
  .island{margin-top:36px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted)}
  .island summary{cursor:pointer;font:600 13px var(--mono);color:var(--text)}
  .island p{font-size:12.5px;max-width:840px}
  .island pre.howto{white-space:pre-wrap}
  #kelyfos-chain{font-size:11px;color:var(--muted);max-height:260px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:28px 0}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px}
  .card .n{font:700 22px var(--mono);color:#e8eef4}
  .card .n.warn{color:var(--warn)} .card .n.ok{color:var(--ok)}
  .card .l{font-size:12px;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-top:4px}
  table.meta{width:100%;border-collapse:collapse;background:var(--panel);
             border:1px solid var(--line);border-radius:6px;margin-bottom:28px}
  table.meta td{padding:8px 16px;border-bottom:1px solid var(--line);font:13px var(--mono)}
  table.meta tr:last-child td{border-bottom:none}
  table.meta td:first-child{color:var(--muted);width:170px}
  h2{font:600 15px var(--sans);letter-spacing:.1em;text-transform:uppercase;
     color:var(--muted);margin:32px 0 12px}
  .row{display:flex;gap:14px;padding:10px 0;border-bottom:1px solid var(--line)}
  .row:last-child{border-bottom:none}
  .t{flex:none;width:96px;color:var(--muted);font:12px var(--mono);padding-top:2px}
  .b{min-width:0;flex:1}
  .title{font:600 14px var(--mono);word-break:break-word}
  .detail{color:var(--muted);font-size:12.5px;margin-top:2px}
  pre{margin:8px 0 0;padding:10px 12px;background:#0c1117;border:1px solid var(--line);
      border-radius:4px;font:12.5px/1.55 var(--mono);white-space:pre-wrap;word-break:break-word;
      max-height:340px;overflow:auto}
  .command .title{color:#e8eef4}
  .command.err .title{color:var(--warn)}
  .file .title{color:var(--amber)}
  .egress .title{color:var(--ok)}
  .egress-blocked .title{color:var(--warn)}
  .oom .title{color:var(--warn)}
  .team .title{color:var(--text)}
  .team-refused .title{color:var(--warn)}
  .secret .title{color:var(--amber)}
  .session .title{color:var(--muted);font-weight:400}
  .store .title{color:var(--amber)}
  .client .title{color:var(--client)}
  .plugin .title{color:var(--client)}

  /* ---------- team lanes ---------- */
  /* One column per agent plus a time gutter. A message between two agents is
     one grid item spanning exactly the columns it connects, which is what makes
     "who told what to whom" readable at a glance instead of reconstructed. */
  .lanes{display:grid;gap:0 10px;align-items:start;margin-bottom:8px}
  .lane-head{position:sticky;top:0;background:var(--bg);padding:8px 0 10px;z-index:1;
             font:600 12px var(--mono);letter-spacing:.08em;text-transform:uppercase;
             color:var(--amber);border-bottom:1px solid var(--line)}
  .lane-head.gutter{color:var(--muted)}
  /* The gutter's column is explicit and load-bearing. Grid's sparse
     auto-placement advances its cursor past every definitely-positioned item,
     so an auto-placed timestamp lands wherever the cursor happens to sit — in
     a lane, on a row it does not belong to. Measured before it was fixed:
     five timestamps at four different x positions and two pairs of rows
     collapsed onto one. Naming column 1 forces a new row instead. */
  .lanes .t{grid-column:1;width:auto;padding:6px 0 0}
  .cell{background:var(--panel);border:1px solid var(--line);border-left:2px solid var(--line);
        border-radius:4px;padding:6px 9px;margin:3px 0;min-width:0}
  .cell .title{font:600 12.5px var(--mono);word-break:break-word}
  .cell .detail{font-size:11.5px;margin-top:1px}
  .cell pre{max-height:150px;font-size:11.5px;margin-top:6px}
  .cell.command{border-left-color:#5b7aa6}
  .cell.command.err{border-left-color:var(--warn)}
  .cell.file{border-left-color:var(--amber)}
  .cell.store{border-left-color:var(--amber)}
  .cell.egress{border-left-color:var(--ok)}
  .cell.egress-blocked,.cell.oom{border-left-color:var(--warn)}
  .cell.secret{border-left-color:var(--amber)}
  .cell.session{border-left-color:var(--muted);background:transparent}
  /* A flow is drawn as a rule between the two lanes rather than a box inside
     one, because the message is the relationship, not either endpoint. */
  .flow{margin:5px 0;padding:4px 10px;border-radius:3px;border:1px dashed var(--line);
        background:rgba(240,166,60,.06);text-align:center;min-width:0}
  .flow .title{font:600 12.5px var(--mono);color:var(--amber);word-break:break-word}
  .flow .detail{font-size:11px;margin-top:1px}
  .flow.team-refused{border-color:rgba(217,106,95,.5);background:rgba(217,106,95,.08)}
  .flow.team-refused .title{color:var(--warn)}
  .lanes-note{color:var(--muted);font-size:12.5px;margin:0 0 14px}
  footer{margin-top:44px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
  @media print{body{background:#fff;color:#111}.card,table.meta,pre{background:#fff}}
</style>
</head><body class="{{if .Lanes}}team{{end}}"><div class="wrap">

<h1>Kelyf<span>OS</span> session report</h1>
<div class="sub">session <span id="kelyfos-session">{{.SessionID}}</span> · {{.Events}} events · generated {{.Generated}}</div>
{{if .SelfCheck}}
<div class="chain bad">The exporter's own check of this record failed — {{.SelfCheck}}.
That is this file reporting a problem with itself. Check it rather than take its word:
<code>kelyfos verify &lt;this file&gt;</code>.</div>
{{end}}
<div class="chain">
  <b>This page does not verify itself.</b> It carries the record it was rendered from —
  <code id="kelyfos-events">{{.Events}}</code> event{{if ne .Events 1}}s{{end}}{{if .ChainHead}}, chain head
  <code id="kelyfos-head">{{.ChainHead}}</code>{{end}} — so that
  somebody else can. <code>kelyfos verify &lt;this file&gt;</code> reads that record out of the
  file and re-runs the chain over it: offline, no key, no network, nothing of ours to trust.
  {{if .Signed.Sig}}<span class="signed">Signed by the key whose fingerprint is
  <code id="kelyfos-fingerprint">{{.Fingerprint}}</code>. <b>That is a fact about this file, not a
  recommendation.</b> It says the holder of that key exported this record — and it is worth exactly what
  knowing the key is worth, so it means something only if you recognise the fingerprint from somewhere
  other than this page.</span>{{end}}
  <span class="limit">The two numbers above are checked against the record too, so this page
  cannot quietly disagree with what it carries. <b>The timeline below is not.</b> It was drawn
  from the record by the exporter, and a page whose text was edited afterwards still carries an
  intact record. <code>kelyfos verify --replay &lt;this file&gt;</code> prints the timeline from
  the record instead, so the two can be compared.</span>
</div>

<div class="cards">
  <div class="card"><div class="n">{{.Summary.Commands}}</div><div class="l">commands</div></div>
  <div class="card"><div class="n{{if .Summary.Failed}} warn{{end}}">{{.Summary.Failed}}</div><div class="l">failed</div></div>
  <div class="card" title="Only writes the host saw: write_file, upload, and the file doors of serve-mcp and the shim. A shell redirect inside the guest is not one of them, so this can read 0 for a session that wrote a file."><div class="n">{{.Summary.FilesWritten}}</div><div class="l">files written <span class="qual">through a tool</span></div></div>
  <div class="card"><div class="n ok">{{.Summary.EgressOK}}</div><div class="l">egress allowed</div></div>
  <div class="card"><div class="n{{if .Summary.EgressBlock}} warn{{end}}">{{.Summary.EgressBlock}}</div><div class="l">egress blocked</div></div>
  <div class="card"><div class="n{{if .Summary.OOMKills}} warn{{end}}">{{.Summary.OOMKills}}</div><div class="l">OOM kills</div></div>
  {{if or .Summary.TeamMessages .Summary.TeamRefused}}<div class="card"><div class="n">{{.Summary.TeamMessages}}</div><div class="l">team messages</div></div>
  <div class="card"><div class="n{{if .Summary.TeamRefused}} warn{{end}}">{{.Summary.TeamRefused}}</div><div class="l">team refused</div></div>{{end}}
  <div class="card"><div class="n">{{.Summary.BootMS}}</div><div class="l">boot ms</div></div>
</div>

<table class="meta">
  <tr><td>image</td><td>{{.Summary.Image}} · {{.Summary.Arch}}</td></tr>
  <tr><td>guest</td><td>kernel {{.Summary.Kernel}} · supervisor {{.Summary.Supervisor}}</td></tr>
  <tr><td>kelyfos</td><td>{{.Summary.Kelyfos}}</td></tr>
  <tr><td>started</td><td>{{.Summary.Started}}</td></tr>
  <tr><td>ended</td><td>{{if .Summary.Ended}}{{.Summary.Ended}} ({{.Summary.EndReason}}){{else}}still running{{end}}</td></tr>
  <tr><td>TLS terminated</td><td>{{.Summary.Terminated}} connection(s) the proxy could read{{if not .Summary.Terminated}} — none{{end}}</td></tr>
  {{if .Summary.Usage}}<tr><td>usage receipt</td><td>
    {{printf "%.2f" .Summary.Usage.CPUSeconds}} CPU-seconds{{if .Summary.Usage.CPUQuota}} · quota {{.Summary.Usage.CPUQuota}}% of one core{{else if .Summary.Usage.Vcpus}} · {{.Summary.Usage.Vcpus}} core(s), no quota{{end}}<br>
    peak RSS {{.Summary.Usage.PeakRSS}} <span style="color:var(--muted)">(the VMM process, which also holds what the host cached for its disks)</span>{{if .Summary.Usage.MemMiB}} · the machine had {{.Summary.Usage.MemMiB}} MiB of RAM{{end}}<br>
    network {{.Summary.Usage.NetIn}} in / {{.Summary.Usage.NetOut}} out · disk {{.Summary.Usage.DiskWrite}} written, {{.Summary.Usage.DiskRead}} read<br>
    <span style="color:var(--muted)">measured on the host, from the VMM's own counters — the guest was not asked</span>
  </td></tr>{{end}}
  <tr><td>ended by</td><td>{{if .Summary.TimedOut}}<span style="color:var(--warn)">the {{.Summary.TimedOut}} budget</span>{{else}}{{.Summary.EndReason}}{{end}}</td></tr>
  <tr><td>secrets used</td><td>{{if .Summary.Secrets}}{{range .Summary.Secrets}}{{.}} {{end}}<br><span style="color:var(--muted)">values are never recorded</span>{{else}}none{{end}}</td></tr>
</table>

{{if .Lanes}}
<h2>{{if .Served}}Sandbox lanes{{else}}Team lanes{{end}}</h2>
{{if .Served}}
<p class="lanes-note">One column per sandbox, in the order they were created. A
call that names no sandbox spans every column; a refused call is drawn like a
refused message, because it is the same thing — the wall saying no, where a
reader can see it. Everything below came from the record embedded at the foot of
this page: one record of what the client asked for, beside what happened.</p>
{{else}}
<p class="lanes-note">One column per agent, in boot order. A message between two
agents spans the columns it connects; store accesses sit inline in the lane of
the agent that made them. Everything below came from the record embedded at the
foot of this page — one record for the whole team, not five to correlate.</p>
{{end}}
<div class="lanes" style="{{.LaneWidth}}">
  <div class="lane-head gutter">time</div>
  {{range .Lanes}}<div class="lane-head">{{.}}</div>{{end}}
  {{range .LaneRows}}
  <div class="t">{{.Time}}</div>
  <div class="{{if .Flow}}flow{{else}}cell{{end}} {{.Kind}}{{if .IsError}} err{{end}}" style="{{.Place}}">
    <div class="title">{{.Title}}</div>
    {{if .Detail}}<div class="detail">{{.Detail}}</div>{{end}}
    {{if .Output}}<pre>{{.Output}}</pre>{{end}}
  </div>
  {{end}}
</div>
{{end}}

<h2>Timeline</h2>
{{range .Rows}}
<div class="row {{.Kind}}{{if .IsError}} err{{end}}">
  <div class="t">{{.Time}}</div>
  <div class="b">
    <div class="title">{{.Title}}</div>
    {{if .Detail}}<div class="detail">{{.Detail}}</div>{{end}}
    {{if .Output}}<pre>{{.Output}}</pre>{{end}}
  </div>
</div>
{{end}}

<details class="island">
<summary>The record this page was rendered from — {{.Events}} event{{if ne .Events 1}}s{{end}}, {{.ChainBytes}} bytes</summary>
<p>Base64 of the session's <code>events.jsonl</code>, exactly as the host wrote it.
<code>kelyfos verify</code> reads it from here. Without KelyfOS, this takes it out:</p>
<pre class="howto">sed -n '/&lt;pre id="kelyfos-chain"&gt;/,/&lt;\/pre&gt;/p' FILE | sed '1d;$d' | base64 -d &gt; events.jsonl</pre>
<pre id="kelyfos-chain">
{{.Chain}}</pre>
{{if .Signed.Sig}}<p>Signed with ed25519 over the chain head and a digest of the record above — not over this
page, so re-exporting the same session produces the same signature.</p>
<pre class="howto">signature <code id="kelyfos-signature">{{.Signed.Sig}}</code>
key       <code id="kelyfos-signing-key">{{.Signed.Key}}</code></pre>{{end}}
</details>

<footer>
Rendered by KelyfOS from the session's flight recorder, which is embedded in this
file rather than summarised by it. Every command, file write and network attempt
the host observed is in that record, and the guest cannot write to it.
Verification checks that no line was altered, and none removed from the beginning
or the middle. <b>A record cut short at its end still verifies</b>, and looks
exactly like a session that is still open — the chain head is what tells them
apart, and only against a head from somewhere else. It does not check that
everything worth recording was recorded, and it is not a signature: anyone who
can rewrite the whole record can recompute every digest. See docs/events.md.
</footer>
</div></body></html>
`
