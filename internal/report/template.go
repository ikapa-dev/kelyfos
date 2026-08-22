package report

// reportHTML is the whole report: one file, no scripts, no external requests.
// A compliance artefact that needs a CDN to render is not one.
const reportHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KelyfOS session {{.SessionID}}</title>
<style>
  :root{
    --bg:#10161d; --panel:#161e28; --line:#26313f; --text:#c9d4de; --muted:#71818f;
    --amber:#f0a63c; --ok:#58c470; --warn:#d96a5f;
    --mono:ui-monospace,"SF Mono","Cascadia Code",Consolas,monospace;
    --sans:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--sans)}
  .wrap{max-width:940px;margin:0 auto;padding:40px 20px 80px}
  h1{font:700 28px/1.2 var(--mono);margin:0;color:#e8eef4}
  h1 span{color:var(--amber)}
  .sub{color:var(--muted);font:13px/1.7 var(--mono);margin-top:8px}
  .chain{display:inline-block;margin-top:14px;padding:6px 12px;border-radius:4px;
         font:600 13px var(--mono)}
  .chain.ok{background:rgba(88,196,112,.12);color:var(--ok);border:1px solid rgba(88,196,112,.35)}
  .chain.bad{background:rgba(217,106,95,.12);color:var(--warn);border:1px solid rgba(217,106,95,.45)}
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
  .secret .title{color:var(--amber)}
  .session .title{color:var(--muted);font-weight:400}
  footer{margin-top:44px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
  @media print{body{background:#fff;color:#111}.card,table.meta,pre{background:#fff}}
</style>
</head><body><div class="wrap">

<h1>Kelyf<span>OS</span> session report</h1>
<div class="sub">session {{.SessionID}} · {{.Events}} events · generated {{.Generated}}</div>
{{if .Verified}}
<div class="chain ok">✓ audit chain intact — {{.Events}} events verified</div>
{{else}}
<div class="chain bad">✗ audit chain FAILED — {{.VerifyNote}}</div>
{{end}}

<div class="cards">
  <div class="card"><div class="n">{{.Summary.Commands}}</div><div class="l">commands</div></div>
  <div class="card"><div class="n{{if .Summary.Failed}} warn{{end}}">{{.Summary.Failed}}</div><div class="l">failed</div></div>
  <div class="card"><div class="n">{{.Summary.FilesWritten}}</div><div class="l">files written</div></div>
  <div class="card"><div class="n ok">{{.Summary.EgressOK}}</div><div class="l">egress allowed</div></div>
  <div class="card"><div class="n{{if .Summary.EgressBlock}} warn{{end}}">{{.Summary.EgressBlock}}</div><div class="l">egress blocked</div></div>
  <div class="card"><div class="n{{if .Summary.OOMKills}} warn{{end}}">{{.Summary.OOMKills}}</div><div class="l">OOM kills</div></div>
  <div class="card"><div class="n">{{.Summary.BootMS}}</div><div class="l">boot ms</div></div>
</div>

<table class="meta">
  <tr><td>image</td><td>{{.Summary.Image}} · {{.Summary.Arch}}</td></tr>
  <tr><td>guest</td><td>kernel {{.Summary.Kernel}} · supervisor {{.Summary.Supervisor}}</td></tr>
  <tr><td>kelyfos</td><td>{{.Summary.Kelyfos}}</td></tr>
  <tr><td>started</td><td>{{.Summary.Started}}</td></tr>
  <tr><td>ended</td><td>{{if .Summary.Ended}}{{.Summary.Ended}} ({{.Summary.EndReason}}){{else}}still running{{end}}</td></tr>
  <tr><td>TLS terminated</td><td>{{.Summary.Terminated}} connection(s) the proxy could read{{if not .Summary.Terminated}} — none{{end}}</td></tr>
  <tr><td>secrets used</td><td>{{if .Summary.Secrets}}{{range .Summary.Secrets}}{{.}} {{end}}<br><span style="color:var(--muted)">values are never recorded</span>{{else}}none{{end}}</td></tr>
</table>

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

<footer>
Rendered by KelyfOS from the session's flight recorder. Every command, file write
and network attempt the host observed is above; the guest cannot write to this
record. Chain verification checks that the file has not been edited since it was
written — see docs/events.md.
</footer>
</div></body></html>
`
