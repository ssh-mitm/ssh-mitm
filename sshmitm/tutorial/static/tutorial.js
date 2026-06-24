let state = null;

const es = new EventSource('/events');
es.onmessage = function(e) {
  const ev = JSON.parse(e.data);
  if      (ev.type === 'state') { state = ev.data; render(); setSshMitmStatus(state.sshmitm_running); }
  else if (ev.type === 'alert') { showAlert(ev.data); }
  // 'activity' events (SSH auth results) are intentionally not displayed —
  // showing them would reveal credentials the user is supposed to discover themselves.
};

function act(name) {
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: name})});
}

function selectTut(id) {
  if (state && state.runner_state === 'running' && id !== state.selected) {
    if (!confirm('A tutorial is still running.\nSwitch anyway?')) return;
  }
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
  const fallback = state.steps[Math.min(state.current_step, state.steps.length - 1)];
  const active = state.steps.find(s => s.active) || fallback;
  if (active) {
    document.getElementById('step-content').innerHTML = active.content_html;
    const hintEl = document.getElementById('hint');
    const hint = active.hint || '';
    hintEl.className = 'hint hint-' + (active.hint_type || 'info');
    if (hint) { hintEl.textContent = hint; hintEl.style.display = 'block'; }
    else { hintEl.style.display = 'none'; }
    if (active.command) {
      document.getElementById('cmd-text').textContent = active.command;
      document.getElementById('cmd-area').style.display = 'block';
    } else {
      document.getElementById('cmd-area').style.display = 'none';
    }
    renderCopyable(active.copyable);
    renderInteractionArea(active.active);
    renderContinueBtn(active.active);
  }
}

let _renderedStepId = null;

function renderInteractionArea(isActive) {
  const area = document.getElementById('interaction-area');
  const active = state.steps ? state.steps.find(s => s.active) : null;
  const stepId = active ? active.id : null;

  // Fully rebuild only when the step changes (prevents input clearing on state updates)
  if (stepId !== _renderedStepId) {
    area.innerHTML = '';
    _renderedStepId = stepId;
    if (!isActive) return;
    _buildInputFields(area);
    return;
  }

  // Same step: update satisfied state and feedback without touching input values
  if (!isActive) return;
  const inputs = (state && state.user_inputs) || [];
  for (const field of inputs) {
    const inp = area.querySelector(`input[data-key="${CSS.escape(field.key)}"]`);
    if (!inp) continue;
    inp.classList.toggle('satisfied', !!field.satisfied);
    if (field.satisfied) {
      const fb = area.querySelector(`.input-feedback[data-key="${CSS.escape(field.key)}"]`);
      if (fb && fb.style.display === 'none') {
        fb.textContent = '✓ Correct!';
        fb.className = 'input-feedback correct';
        fb.style.display = 'block';
      }
    }
  }
}

function _buildInputFields(area) {
  const inputs = (state && state.user_inputs) || [];
  if (!inputs.length) return;

  for (const field of inputs) {
    const group = document.createElement('div');
    group.className = 'input-group';
    const prompt = document.createElement('div');
    prompt.className = 'input-prompt';
    prompt.textContent = field.prompt || field.key.replace(/_/g, ' ');
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.autocomplete = 'off';
    inp.spellcheck = false;
    inp.dataset.key = field.key;
    const fb = document.createElement('div');
    fb.className = 'input-feedback';
    fb.style.display = 'none';
    fb.dataset.key = field.key;
    group.appendChild(prompt); group.appendChild(inp); group.appendChild(fb);
    area.appendChild(group);
  }

  const submitBtn = document.createElement('button');
  submitBtn.id = 'submit-all-btn';
  submitBtn.className = 'btn-submit-all';
  submitBtn.textContent = 'Submit';
  submitBtn.onclick = submitAll;
  area.appendChild(submitBtn);
}

function renderContinueBtn(isActive) {
  const area = document.getElementById('interaction-area');
  const existing = area.querySelector('.btn-continue');
  if (existing) existing.remove();
  if (!isActive) return;
  const ready = state && state.step_ready;
  const active = state.steps ? state.steps.find(s => s.active) : null;
  const hasContinue = !!(active && active.has_continue);
  if (!ready && !hasContinue) return;
  const canClick = ready || hasContinue;
  const btn = document.createElement('button');
  btn.className = 'btn-continue' + (canClick ? '' : ' disabled');
  btn.textContent = ready ? 'Continue →' : 'Continue';
  btn.disabled = !canClick;
  btn.onclick = canClick ? advance : null;
  area.appendChild(btn);
}

function submitAll() {
  const area = document.getElementById('interaction-area');
  const values = {};
  area.querySelectorAll('input[data-key]').forEach(inp => {
    values[inp.dataset.key] = inp.value;
  });
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'submit_all', values: values})
  }).then(r => r.json()).then(data => {
    for (const [key, correct] of Object.entries(data.results || {})) {
      const fb = area.querySelector(`.input-feedback[data-key="${CSS.escape(key)}"]`);
      if (!fb) continue;
      fb.textContent = correct ? '✓ Correct!' : '✗ Wrong — check the SSH-MITM terminal and try again.';
      fb.className = 'input-feedback ' + (correct ? 'correct' : 'wrong');
      fb.style.display = 'block';
    }
  });
}

function advance() {
  fetch('/action', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'advance'})});
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


fetch('/state').then(r => r.json()).then(d => { state = d; render(); setSshMitmStatus(state.sshmitm_running); });
