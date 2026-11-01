// Ward Zero replay: loads a simulated incident and plays it back.
const DAY = 1440;
const SCENARIOS = [
  { id: 'none', label: 'No defences' },
  { id: 'offline_backups', label: 'Offline backups' },
  { id: 'admin_tiering', label: 'Admin tiering' },
  { id: 'all', label: 'All defences' },
];
const ZONES = [
  ['admin', 'Admin'], ['clinical', 'Wards'], ['ed', 'Emergency'], ['dmz', 'Remote access'],
  ['imaging', 'Imaging'], ['iot', 'Medical devices'], ['servers', 'Servers'], ['backup', 'Backups'],
];
const STATES = {
  clean: { label: 'Clean', glyph: '' },
  compromised: { label: 'Compromised', glyph: '!' },
  encrypted: { label: 'Encrypted', glyph: '🔒' },
  isolated: { label: 'Isolated', glyph: '' },
  restored: { label: 'Restored', glyph: '✓' },
};
const LOG_KINDS = new Set(['compromised', 'credentials', 'domain_admin', 'blocked', 'alert', 'isolated', 'panic', 'contained', 'backups', 'detonate']);

const $ = (id) => document.getElementById(id);
const tip = $('tip');
let run = null;
let compromisedAt = {};
let playing = null;

const clock = (m) => {
  const d = Math.floor(m / DAY), h = Math.floor((m % DAY) / 60), mm = m % 60;
  return `Day ${d + 1} ${String(h).padStart(2, '0')}:${String(mm).padStart(2, '0')}`;
};
const hours = (m) => (m == null ? '—' : `${Math.round(m / 60)} h`);
const attackUrl = (t) => `https://attack.mitre.org/techniques/${t.replace('.', '/')}/`;

function stateAt(id, t) {
  const enc = run.encrypted[id], res = run.restored[id];
  if (enc != null && t >= enc) return res != null && t >= res ? 'restored' : 'encrypted';
  const iso = run.isolated[id], until = run.isolated_until[id];
  if (iso != null && t >= iso && t < until) return 'isolated';
  const c = compromisedAt[id];
  if (c != null && t >= c && !(iso != null && t >= iso)) return 'compromised';
  return 'clean';
}

function hostDown(id, t) {
  const s = stateAt(id, t);
  return s === 'encrypted' || s === 'isolated';
}

function serviceDown(svc, t) {
  if (svc.needs.some((n) => hostDown(n, t))) return true;
  return svc.any_of.length > 0 && svc.any_of.every((n) => hostDown(n, t));
}

// ---------------------------------------------------------------- map

const W = 820, PAD = 14, COLS = 4, ZW = (W - PAD * (COLS + 1)) / COLS, CELL = 26, SQ = 20;
let hostNodes = {};

function drawMap() {
  const svg = $('map');
  svg.innerHTML = '';
  hostNodes = {};
  const byZone = Object.fromEntries(ZONES.map(([z]) => [z, []]));
  run.hosts.forEach((h) => byZone[h.zone]?.push(h));
  const perRow = Math.floor((ZW - 16) / CELL);
  const rowHeights = [0, 1].map((r) =>
    Math.max(...ZONES.slice(r * COLS, r * COLS + COLS).map(([z]) => Math.ceil(byZone[z].length / perRow))) * CELL + 40,
  );
  const H = PAD * 3 + rowHeights[0] + rowHeights[1];
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  const ns = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs, parent) => {
    const e = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
    parent.appendChild(e);
    return e;
  };
  ZONES.forEach(([z, label], i) => {
    const col = i % COLS, row = Math.floor(i / COLS);
    const x = PAD + col * (ZW + PAD), y = PAD + (row ? rowHeights[0] + PAD : 0);
    el('rect', { x, y, width: ZW, height: rowHeights[row], rx: 10, class: 'zone-box' }, svg);
    el('text', { x: x + 10, y: y + 18, class: 'zone-label' }, svg).textContent = label;
    byZone[z].forEach((h, j) => {
      const hx = x + 10 + (j % perRow) * CELL, hy = y + 28 + Math.floor(j / perRow) * CELL;
      const g = el('g', { class: 'host clean', tabindex: 0 }, svg);
      el('rect', { x: hx, y: hy, width: SQ, height: SQ, rx: 4, class: 'body' }, g);
      el('rect', { x: hx - 2, y: hy - 2, width: SQ + 4, height: SQ + 4, rx: 6, class: 'ring' }, g).style.display = 'none';
      const glyph = el('text', { x: hx + SQ / 2, y: hy + SQ / 2 + 3.5, class: 'glyph' }, g);
      el('rect', { x: hx - 3, y: hy - 3, width: SQ + 6, height: SQ + 6, class: 'hit' }, g);
      const show = (ev) => {
        const t = +$('time').value;
        const s = stateAt(h.id, t);
        tip.innerHTML = `<strong>${h.id}</strong> · ${h.kind.replace('-', ' ')}<br>${STATES[s].label}` +
          `<br><span style="opacity:.75">${h.patched ? 'patched' : 'unpatched'} · ${h.edr ? 'EDR agent' : 'no EDR'}</span>`;
        tip.hidden = false;
        const r = (ev.currentTarget || g).getBoundingClientRect();
        tip.style.left = `${Math.min(r.right + 8, innerWidth - 270)}px`;
        tip.style.top = `${r.top - 6}px`;
      };
      g.addEventListener('mouseenter', show);
      g.addEventListener('focus', show);
      g.addEventListener('mouseleave', () => (tip.hidden = true));
      g.addEventListener('blur', () => (tip.hidden = true));
      hostNodes[h.id] = { g, glyph, ring: g.querySelector('.ring') };
    });
  });
}

function drawLegend() {
  $('legend').innerHTML = Object.entries(STATES)
    .map(([k, v]) => {
      const dash = k === 'isolated' ? 'stroke-dasharray="3 2" stroke-width="2"' : '';
      const fill = k === 'isolated' ? 'var(--surface)' : `var(--${k})`;
      return `<li><svg viewBox="0 0 14 14"><rect x="1" y="1" width="12" height="12" rx="3" fill="${fill}" stroke="${k === 'isolated' ? 'var(--isolated)' : k === 'compromised' ? 'var(--ink)' : 'none'}" ${dash}/></svg>${v.label}</li>`;
    })
    .join('');
}

// ---------------------------------------------------------------- frame

function render() {
  const t = +$('time').value;
  $('clock').textContent = clock(t);
  for (const [id, n] of Object.entries(hostNodes)) {
    const s = stateAt(id, t);
    n.g.setAttribute('class', `host ${s}`);
    n.ring.style.display = s === 'compromised' ? '' : 'none';
    n.glyph.textContent = STATES[s].glyph;
  }
  $('services').innerHTML = run.services
    .map((svc) => {
      const down = serviceDown(svc, t);
      return `<li><span>${svc.name}${svc.critical ? '<span class="crit">critical</span>' : ''}</span>` +
        `<span class="pill ${down ? 'down' : 'up'}">${down ? '✕ Down' : '● Up'}</span></li>`;
    })
    .join('');
  const shown = run.events.filter((e) => e.t <= t && LOG_KINDS.has(e.kind)).slice(-60).reverse();
  $('log').innerHTML = shown.length
    ? shown
        .map((e) => `<li><time>${clock(e.t).replace('Day ', 'D')}</time><span>${e.host ? `<strong>${e.host}</strong> · ` : ''}${e.detail}` +
          (e.technique ? ` <a class="tech" href="${attackUrl(e.technique)}" target="_blank" rel="noopener">${e.technique}</a>` : '') + '</span></li>')
        .join('')
    : '<li><span>Quiet so far.</span></li>';
}

function drawMarks() {
  const max = +$('time').max, m = run.metrics;
  const marks = [
    [m.time_to_domain_admin, 'Domain admin'],
    [m.first_alert, 'First alert'],
    [m.detonated_at, 'Encryption'],
    [m.contained_at, 'Contained'],
  ].filter(([t]) => t != null);
  // Keep labels from colliding: drop a label that sits too close to the previous one.
  let last = -Infinity;
  $('marks').innerHTML = marks
    .sort((a, b) => a[0] - b[0])
    .map(([t, label]) => {
      const pct = (t / max) * 100;
      const text = pct - last < 9 ? '' : label;
      if (text) last = pct;
      return `<span style="left:${pct}%" title="${label}: ${clock(t)}">${text}</span>`;
    })
    .join('');
}

function drawHeadline() {
  const m = run.metrics;
  const stats = [
    [m.hosts_encrypted, 'hosts encrypted'],
    [m.backups_destroyed ? 'Yes' : 'No', 'backups destroyed'],
    [`${Math.round(m.diversion_hours)} h`, 'ambulances diverted'],
    [`${Math.round(m.service_downtime_hours['Patient records (EHR)'])} h`, 'patient records down'],
  ];
  $('headline').innerHTML = stats.map(([v, k]) => `<div class="stat"><div class="v">${v}</div><div class="k">${k}</div></div>`).join('');
}

async function load(id) {
  run = await (await fetch(`data/run-${id}.json`)).json();
  compromisedAt = {};
  run.events.forEach((e) => {
    if (e.kind === 'compromised' && compromisedAt[e.host] == null) compromisedAt[e.host] = e.t;
  });
  const last = Math.max(0, ...Object.values(run.restored), ...run.events.map((e) => e.t));
  $('time').max = Math.min(21 * DAY, Math.max(3 * DAY, Math.ceil((last + DAY / 2) / 60) * 60));
  $('time').value = 0;
  drawMap();
  drawHeadline();
  drawMarks();
  render();
  document.querySelectorAll('#scenarios button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.id === id)));
}

function togglePlay() {
  if (playing) {
    clearInterval(playing);
    playing = null;
    $('play').textContent = '▶';
    return;
  }
  const slider = $('time');
  if (+slider.value >= +slider.max) slider.value = 0;
  $('play').textContent = '❚❚';
  playing = setInterval(() => {
    const step = Math.max(10, Math.round(+slider.max / 600));
    slider.value = Math.min(+slider.max, +slider.value + step);
    render();
    if (+slider.value >= +slider.max) togglePlay();
  }, 33);
}

// ---------------------------------------------------------------- ranking

async function drawRanking() {
  const data = await (await fetch('data/ranking.json')).json();
  $('rankingSub').textContent = `Average hours the emergency department diverts ambulances, over ${data.runs} seeded incidents per setup. Every setup faces the same attacks.`;
  const max = Math.max(...data.rows.map((r) => r.diversion_hours_mean)) || 1;
  $('bars').innerHTML = data.rows
    .map((r, i) => {
      const w = (r.diversion_hours_mean / max) * 100;
      return `<div class="bar-row${i === 0 ? ' base' : ''}" data-i="${i}" tabindex="0"><div class="name">${r.label}</div>` +
        `<div class="track2"><div class="fill" style="width:${w}%"></div></div><div class="val">${Math.round(r.diversion_hours_mean)} h</div></div>`;
    })
    .join('');
  document.querySelectorAll('.bar-row').forEach((row) => {
    const r = data.rows[+row.dataset.i];
    const show = () => {
      tip.innerHTML = `<strong>${r.label}</strong><br>Encryption happened in ${Math.round(r.detonated * 100)}% of runs` +
        `<br>${r.hosts_encrypted_mean.toFixed(1)} hosts encrypted on average<br>Backups lost in ${Math.round(r.backups_destroyed * 100)}%` +
        `<br>Worst 10%: ${Math.round(r.diversion_hours_p90)} h of diversion`;
      tip.hidden = false;
      const b = row.getBoundingClientRect();
      tip.style.left = `${Math.min(b.left + 160, innerWidth - 270)}px`;
      tip.style.top = `${b.bottom + 4}px`;
    };
    row.addEventListener('mouseenter', show);
    row.addEventListener('focus', show);
    row.addEventListener('mouseleave', () => (tip.hidden = true));
    row.addEventListener('blur', () => (tip.hidden = true));
  });
  const head = ['Setup', 'Encrypted at all', 'Hosts encrypted', 'Backups lost', 'ED diversion (mean)', 'Worst 10%', 'Records down'];
  $('rankTable').innerHTML = `<table><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>` +
    data.rows
      .map((r) => `<tr><td>${r.label}</td><td class="n">${Math.round(r.detonated * 100)}%</td><td class="n">${r.hosts_encrypted_mean.toFixed(1)}</td>` +
        `<td class="n">${Math.round(r.backups_destroyed * 100)}%</td><td class="n">${Math.round(r.diversion_hours_mean)} h</td>` +
        `<td class="n">${Math.round(r.diversion_hours_p90)} h</td><td class="n">${Math.round(r.ehr_down_hours_mean)} h</td></tr>`)
      .join('') + '</tbody></table>';
  $('tableToggle').addEventListener('click', () => {
    const t = $('rankTable'), b = $('bars');
    t.hidden = !t.hidden;
    b.hidden = !t.hidden;
    $('tableToggle').textContent = t.hidden ? 'Show as table' : 'Show as chart';
  });
}

// ---------------------------------------------------------------- start

$('scenarios').innerHTML = SCENARIOS.map((s) => `<button role="radio" data-id="${s.id}">${s.label}</button>`).join('');
$('scenarios').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (b) {
    if (playing) togglePlay();
    load(b.dataset.id);
  }
});
$('time').addEventListener('input', render);
$('play').addEventListener('click', togglePlay);
drawLegend();
load('none');
drawRanking();
