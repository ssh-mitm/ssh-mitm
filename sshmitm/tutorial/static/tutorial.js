let state = null;

const es = new EventSource('/events');
es.onmessage = function(e) {
  const ev = JSON.parse(e.data);
  if (ev.type === 'state') { state = ev.data; render(); }
  else if (ev.type === 'auth_event') { appendEv(ev.data); }
};

function act(name) {
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: name})});
}

function selectTut(id) {
  if (state && state.runner_state === 'running' && id !== state.selected) {
    if (!confirm('A tutorial is still running.\nSwitch anyway?')) return;
  }
  document.getElementById('event-log').innerHTML = '';
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'select', tutorial_id: id})});
}

function copyCmd() {
  const text = document.getElementById('cmd-text').textContent;
  navigator.clipboard.writeText(text).then(() => {
    const b = document.getElementById('copy-btn');
    b.textContent = '✓ Copied'; b.classList.add('copied');
    setTimeout(() => { b.textContent = '📋 Copy'; b.classList.remove('copied'); }, 1500);
  });
}

function renderCopyable(copyable) {
  const area = document.getElementById('copyable-area');
  area.innerHTML = '';
  const entries = Object.entries(copyable || {});
  if (!entries.length) { area.style.display = 'none'; return; }
  area.style.display = 'flex';
  for (const [k, v] of entries) {
    const wrap = document.createElement('div');
    const label = k.replace(/_/g, ' ');
    wrap.innerHTML = '<div class="copy-label"></div>'
      + '<div class="cmd-box"><span class="cmd-text"></span>'
      + '<button class="copy-btn">📋 Copy</button></div>';
    wrap.querySelector('.copy-label').textContent = label;
    wrap.querySelector('.cmd-text').textContent = String(v);
    const btn = wrap.querySelector('.copy-btn');
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(String(v)).then(() => {
        btn.textContent = '✓ Copied'; btn.classList.add('copied');
        setTimeout(() => { btn.innerHTML = '📋 Copy'; btn.classList.remove('copied'); }, 1500);
      });
    });
    area.appendChild(wrap);
  }
}

function appendEv(d) {
  const log = document.getElementById('event-log');
  const div = document.createElement('div');
  const ok = d.ok;
  div.innerHTML = `<span style="color:#888">${d.ts}</span> `
    + `<span class="${ok ? 'ev-ok' : 'ev-fail'}">${ok ? '✓' : '✗'}</span>  `
    + `<span style="color:#6c7a99">${d.method.padEnd(20)}</span> user=${JSON.stringify(d.username)}`;
  log.appendChild(div); log.scrollTop = log.scrollHeight;
}

function render() {
  if (!state) return;
  renderSidebar();
  if (state.selected) {
    document.getElementById('placeholder').style.display = 'none';
    document.getElementById('tview').style.display = 'flex';
    renderSteps(); renderBtns();
  } else {
    document.getElementById('placeholder').style.display = 'flex';
    document.getElementById('tview').style.display = 'none';
  }
}

function renderSidebar() {
  const cats = {};
  for (const t of state.tutorials) (cats[t.category] = cats[t.category] || []).push(t);
  let h = '';
  for (const [cat, tuts] of Object.entries(cats)) {
    h += `<div class="category">${cat}</div>`;
    for (const t of tuts) {
      const active = t.id === state.selected;
      const running = active && state.runner_state === 'running';
      const icon = running ? '&#9654;' : t.completed ? '&#10003;' : '&#9675;';
      const cls = ['titem', active ? 'active' : '', t.completed ? 'completed' : '', running ? 'running' : ''].filter(Boolean).join(' ');
      h += `<div class="${cls}" onclick="selectTut('${t.id}')"><span class="icon">${icon}</span>${t.title}</div>`;
    }
  }
  document.getElementById('sidebar').innerHTML = h;
}

function renderSteps() {
  let h = '';
  for (const s of state.steps) {
    const cls = 'step' + (s.done ? ' done' : s.active ? ' active' : '');
    const icon = s.done ? '&#10003;' : s.active ? '&#9654;' : '&#9675;';
    h += `<div class="${cls}"><span>${icon}</span>${s.title}</div>`;
  }
  document.getElementById('step-list').innerHTML = h;
  const active = state.steps.find(s => s.active) || state.steps[state.steps.length - 1];
  if (active) {
    document.getElementById('step-content').innerHTML = active.content_html;
    const hintEl = document.getElementById('hint');
    const hint = active.hint || '';
    if (hint) { hintEl.textContent = hint; hintEl.style.display = 'block'; }
    else { hintEl.style.display = 'none'; }
    if (active.command) {
      document.getElementById('cmd-text').textContent = active.command;
      document.getElementById('cmd-area').style.display = 'block';
    } else {
      document.getElementById('cmd-area').style.display = 'none';
    }
    renderCopyable(active.copyable);
  }
}

let _countdownTimer = null;

function renderBtns() {
  const s = state.runner_state, sel = !!state.selected;
  const done = s === 'completed';
  const tut = state.tutorials.find(t => t.id === state.selected);
  document.getElementById('tut-title').textContent = tut ? tut.title : '';
  document.getElementById('completion-banner').style.display = done ? 'block' : 'none';
  document.getElementById('btn-start').disabled = !sel || s === 'running' || done;
  document.getElementById('btn-stop').disabled = s !== 'running';
  if (done) {
    if (!_countdownTimer) startCountdown(8);
  } else {
    clearCountdown();
  }
}

function startCountdown(sec) {
  const msg = document.getElementById('countdown-msg');
  msg.textContent = ` — closing in ${sec}s`;
  _countdownTimer = setInterval(() => {
    sec--;
    if (sec <= 0) {
      clearInterval(_countdownTimer); _countdownTimer = null;
      msg.textContent = ' — closing…';
    } else {
      msg.textContent = ` — closing in ${sec}s`;
    }
  }, 1000);
}

function clearCountdown() {
  if (_countdownTimer) { clearInterval(_countdownTimer); _countdownTimer = null; }
  const msg = document.getElementById('countdown-msg');
  if (msg) msg.textContent = '';
}

fetch('/state').then(r => r.json()).then(d => { state = d; render(); });
