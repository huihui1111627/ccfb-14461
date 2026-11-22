package main

// indexHTML is the single-page compiler UI. It is self-contained: paste a rule
// set, press Compile, and the page shows the plain-prefix cost, the optimised
// table, the compression ratio, the per-rule cost, and the entry list.
const indexHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>tcamc - ACL to TCAM compiler</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#667;--line:#e3e3e8;--accent:#2456a6;--good:#0a7d32;--bad:#b00020;--soft:#f6f7f9}
@media(prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8e8ec;--mut:#9aa0aa;--line:#2b2f36;--accent:#7aa2e8;--soft:#1b1e24}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{padding:1.2rem 1.5rem;border-bottom:1px solid var(--line)}
h1{font-size:1.15rem;margin:0}
h1 span{color:var(--mut);font-weight:400}
main{display:grid;grid-template-columns:minmax(320px,42%) 1fr;gap:0;min-height:calc(100vh - 64px)}
@media(max-width:900px){main{grid-template-columns:1fr}}
.pane{padding:1.2rem 1.5rem;overflow:auto}
.pane.left{border-right:1px solid var(--line)}
textarea{width:100%;height:58vh;min-height:280px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
  padding:.7rem;border:1px solid var(--line);border-radius:8px;background:var(--soft);color:var(--fg);resize:vertical}
.bar{display:flex;gap:.6rem;align-items:center;margin:.7rem 0}
button{font:inherit;padding:.45rem 1rem;border-radius:7px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}
button.ghost{background:transparent;color:var(--accent)}
button:disabled{opacity:.5;cursor:progress}
input[type=number]{width:7rem;font:inherit;padding:.35rem .5rem;border:1px solid var(--line);border-radius:6px;background:var(--soft);color:var(--fg)}
label{color:var(--mut)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.6rem;margin:.4rem 0 1rem}
.stat{border:1px solid var(--line);border-radius:9px;padding:.6rem .7rem;background:var(--soft)}
.stat .v{font-size:1.35rem;font-weight:650;font-variant-numeric:tabular-nums}
.stat .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.good{color:var(--good)}.bad{color:var(--bad)}
h2{font-size:.95rem;margin:1.3rem 0 .5rem;letter-spacing:.01em}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
td.n{text-align:right;font-variant-numeric:tabular-nums}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
.entries{max-height:46vh;overflow:auto;border:1px solid var(--line);border-radius:8px}
.err{border:1px solid var(--bad);border-radius:8px;padding:.7rem .9rem;color:var(--bad);background:color-mix(in srgb,var(--bad) 8%,transparent);white-space:pre-wrap}
.muted{color:var(--mut)}
.tag{display:inline-block;padding:.05rem .4rem;border-radius:5px;background:var(--soft);border:1px solid var(--line);font-size:11px;margin-right:.25rem}
</style></head><body>
<header><h1>tcamc <span>&mdash; access-control rules to ternary CAM entries</span></h1></header>
<main>
<section class="pane left">
  <textarea id="src" spellcheck="false">__EXAMPLE__</textarea>
  <div class="bar">
    <button id="go">Compile</button>
    <button id="sample" class="ghost">Reset example</button>
    <label for="cap">capacity</label>
    <input id="cap" type="number" value="2000" min="16" step="16">
  </div>
  <p class="muted" style="font-size:12px">Fields: src_ip, dst_ip (prefix), src_port, dst_port (ranges),
  proto, vlan, dscp (value/mask), est (0/1). A range is lo-hi; a prefix is a.b.c.d/len.</p>
</section>
<section class="pane right" id="out">
  <p class="muted">Press Compile to see the table.</p>
</section>
</main>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[<>&"]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
const example = __EXAMPLE__;
$('#sample').onclick = () => { $('#src').value = example; };
$('#go').onclick = compile;
$('#src').addEventListener('keydown', e => { if ((e.metaKey||e.ctrlKey) && e.key === 'Enter') compile(); });
async function compile() {
  $('#go').disabled = true;
  const body = JSON.stringify({ruleset: $('#src').value, capacity: parseInt($('#cap').value,10)||2000});
  try {
    const r = await fetch('/api/compile', {method:'POST', headers:{'content-type':'application/json'}, body});
    const d = await r.json();
    render(d);
  } catch (e) {
    $('#out').innerHTML = '<div class="err">'+esc(e.message)+'</div>';
  } finally {
    $('#go').disabled = false;
  }
}
function render(d) {
  if (d.error) { $('#out').innerHTML = '<h2>error</h2><div class="err">'+esc(d.error)+'</div>'; return; }
  const r = d.report;
  let h = '';
  h += '<div class="stats">';
  h += stat('plain prefix rows', r.naive_entries);
  h += stat('optimised rows', r.optimized_entries);
  h += stat('compression', r.ratio.toFixed(2)+'x', r.ratio >= 1 ? 'good' : '');
  h += stat('capacity', r.capacity);
  h += r.fits ? stat('headroom', r.capacity - r.optimized_entries, 'good')
              : stat('short by', r.shortfall, 'bad');
  h += '</div>';
  if (r.encoder_entries) h += '<p class="muted">value-to-label encoder: '+r.encoder_entries+' shared rows</p>';
  h += '<h2>ACLs</h2><table><tr><th>ACL</th><th class="n">ports</th><th class="n">rules</th><th class="n">plain</th><th class="n">opt</th><th class="n">ratio</th><th>labelled</th></tr>';
  for (const p of r.plans) {
    h += '<tr><td>'+esc(p.name)+'</td><td class="n">'+p.bindings+'</td><td class="n">'+p.rules+'</td><td class="n">'+p.naive_entries+
         '</td><td class="n">'+p.optimized_entries+'</td><td class="n">'+esc(p.ratio)+'</td><td class="muted">'+
         (p.labelled_fields||[]).map(esc).join(' ')+'</td></tr>';
  }
  h += '</table>';
  if (r.worst_rules && r.worst_rules.length) {
    h += '<h2>Most expensive rules</h2><table><tr><th>rule</th><th class="n">rows</th><th class="n">plain</th><th>why</th><th>comment</th></tr>';
    for (const w of r.worst_rules.slice(0,12)) {
      h += '<tr><td class="mono">'+esc(w.rule_id)+'</td><td class="n">'+w.entries+'</td><td class="n">'+(w.naive_entries||0)+
           '</td><td class="muted">'+esc(w.reason||'')+'</td><td>'+esc(w.comment||'')+'</td></tr>';
    }
    h += '</table>';
  }
  if (r.suggestions && r.suggestions.length) {
    h += '<h2>Cheaper equivalent spellings</h2><table><tr><th>rule</th><th>kind</th><th>finding</th></tr>';
    for (const s of r.suggestions) {
      h += '<tr><td class="mono">'+esc(s.rule_id)+'</td><td><span class="tag">'+esc(s.kind)+'</span></td><td>'+esc(s.message)+
           (s.rewrite ? '<div class="muted">'+esc(s.rewrite)+'</div>' : '')+'</td></tr>';
    }
    h += '</table>';
  }
  for (const a of d.acls || []) {
    h += '<h2>'+esc(a.name)+' &mdash; '+a.entries.length+' rows, '+a.width+'-bit key</h2>';
    h += '<p class="muted">fields: '+a.fields.map(f =>
        (f.labelled ? f.field+' (labels, '+f.intervals+' intervals)' : f.field)+'['+f.offset+':'+f.pack_width+']').join(' &middot; ')+'</p>';
    h += '<div class="entries"><table><tr><th>row</th><th>action</th><th>rule</th><th>key</th><th>mask</th></tr>';
    for (const e of a.entries) {
      h += '<tr><td class="n">'+e.row+'</td><td>'+esc(e.action)+'</td><td class="mono">'+esc(e.rule)+
           '</td><td class="mono">'+esc(e.key)+'</td><td class="mono">'+esc(e.mask)+'</td></tr>';
    }
    h += '</table></div>';
  }
  $('#out').innerHTML = h;
}
function stat(k, v, cls) { return '<div class="stat"><div class="v '+(cls||'')+'">'+esc(v)+'</div><div class="k">'+esc(k)+'</div></div>'; }
</script>
</body></html>`
