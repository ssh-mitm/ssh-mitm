let state = null;

const ACTIVITY_ICONS = {success: '✓', warning: '⚠', error: '✗', info: '·'};
const SOURCE_LABELS  = {sshmitm: 'SSH-MITM', mockserver: 'Mock'};

const es = new EventSource('/events');
es.onmessage = function(e) {
  const ev = JSON.parse(e.data);
  if      (ev.type === 'state')    { state = ev.data; render(); setSshMitmStatus(state.sshmitm_running); }
  else if (ev.type === 'activity') { appendActivity(ev.data); }
  else if (ev.type === 'alert')    { showAlert(ev.data); }
};

function act(name) {
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: name})});
}

function selectTut(id) {
  if (state && state.runner_state === 'running' && id !== state.selected) {
    if (!confirm('A tutorial is still running.\nSwitch anyway?')) return;
  }
  document.getElementById('activity-log').innerHTML = '';
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'select', tutorial_id: id})});
}

function setSshMitmStatus(running) {
  const el = document.getElementById('sshmitm-status');
  el.classList.toggle('connected', !!running);
  el.querySelector('.status-label').textContent = running ? 'SSH-MITM connected' : 'SSH-MITM';
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

function appendActivity(d) {
  const log = document.getElementById('activity-log');
  const div = document.createElement('div');
  const type = d.type || 'info';
  const icon = ACTIVITY_ICONS[type] || '·';
  const srcLabel = SOURCE_LABELS[d.source] || d.source || '';
  const srcCls = d.source === 'sshmitm' ? 'av-ssh' : 'av-mock';
  let body = `<span class="av-title">${_esc(d.title)}</span>`;
  if (d.detail) body += `<div class="av-detail">${_esc(d.detail)}</div>`;
  if (d.hint)   body += `<div class="av-hint">${_esc(d.hint)}</div>`;
  const srcBadgeCls = d.source === 'sshmitm' ? 'src-sshmitm' : 'src-mock';
  div.className = `av ${type} ${srcCls}`;
  div.innerHTML = `<span class="av-icon">${icon}</span>`
    + `<span class="av-body">${body}</span>`
    + `<span class="av-source ${srcBadgeCls}">${srcLabel}</span>`
    + `<span class="av-ts">${d.ts}</span>`;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

function showAlert(d) {
  const box = document.getElementById('alert-box');
  if (!box) return;
  box.className = d.type ? `type-${d.type}` : '';
  document.getElementById('alert-title').textContent = d.title || '';
  const detailEl = document.getElementById('alert-detail');
  detailEl.textContent = d.detail || '';
  detailEl.style.display = d.detail ? 'block' : 'none';
  const hintEl = document.getElementById('alert-hint');
  const hintText = document.getElementById('alert-hint-text');
  if (d.hint) {
    hintText.textContent = d.hint;
    hintEl.style.display = 'flex';
    const btn = document.getElementById('alert-copy-btn');
    btn.onclick = () => navigator.clipboard.writeText(d.hint).then(() => {
      btn.textContent = '✓ Copied'; btn.classList.add('copied');
      setTimeout(() => { btn.innerHTML = '&#128203; Copy'; btn.classList.remove('copied'); }, 1500);
    });
  } else {
    hintEl.style.display = 'none';
  }
  box.style.display = 'flex';
}

function dismissAlert() {
  const box = document.getElementById('alert-box');
  if (box) box.style.display = 'none';
}

function _esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
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
    renderInputArea(active.input_prompt, active.active);
  }
}

function renderInputArea(prompt, isActive) {
  const area = document.getElementById('input-area');
  const fb   = document.getElementById('input-feedback');
  if (prompt && isActive) {
    document.getElementById('input-prompt').textContent = prompt;
    document.getElementById('input-value').value = '';
    fb.style.display = 'none';
    area.style.display = 'block';
  } else {
    area.style.display = 'none';
  }
}

function submitInput() {
  const value = document.getElementById('input-value').value;
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'submit_input', value: value})
  }).then(r => r.json()).then(data => {
    const fb = document.getElementById('input-feedback');
    if (data.correct) {
      fb.textContent = '✓ Correct!';
      fb.className = 'input-feedback correct';
    } else {
      fb.textContent = '✗ Wrong — check the SSH-MITM terminal and try again.';
      fb.className = 'input-feedback wrong';
    }
    fb.style.display = 'block';
  });
}

let _completionShown = false;

function renderBtns() {
  const s = state.runner_state, sel = !!state.selected;
  const done = s === 'completed';
  const tut = state.tutorials.find(t => t.id === state.selected);
  document.getElementById('tut-title').textContent = tut ? tut.title : '';
  document.getElementById('completion-banner').style.display = done ? 'block' : 'none';
  document.getElementById('btn-start').disabled = !sel || s === 'running';
  document.getElementById('btn-stop').disabled = s !== 'running';
  if (done && !_completionShown) {
    _completionShown = true;
    document.getElementById('completion-dialog').style.display = 'flex';
  }
  if (!done) {
    _completionShown = false;
    document.getElementById('completion-dialog').style.display = '';
  }
}

function dismissCompletion() {
  document.getElementById('completion-dialog').style.display = '';
  // Hard-stop the mock server via stop action so port is freed before next start
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'stop'})});
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('input-value').addEventListener('keydown', e => {
    if (e.key === 'Enter') submitInput();
  });
});

fetch('/state').then(r => r.json()).then(d => { state = d; render(); setSshMitmStatus(state.sshmitm_running); });
