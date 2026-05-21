/**
 * PAT - Password Analysis Tool
 * Frontend JavaScript
 */

/* ========== STATE ========== */
let currentPassword = '';
let analysisTimeout = null;
let generatedPassword = '';
let terminalLines = [];
let hackerSimRunning = false;

/* ========== TYPEWRITER ON LANDING ========== */
const TAGLINES = [
  'Real-Time Password Security Intelligence',
  'Crack Time Estimation. Entropy Analysis.',
  'Know Your Vulnerabilities Before Hackers Do.',
  'Military-Grade Password Intelligence.'
];
let taglineIdx = 0;
let charIdx = 0;
let isDeleting = false;

function typewriterStep() {
  const el = document.getElementById('typewriter');
  if (!el) return;

  const text = TAGLINES[taglineIdx];
  if (!isDeleting) {
    el.textContent = text.substring(0, charIdx + 1);
    charIdx++;
    if (charIdx === text.length) {
      isDeleting = true;
      setTimeout(typewriterStep, 2000);
      return;
    }
  } else {
    el.textContent = text.substring(0, charIdx - 1);
    charIdx--;
    if (charIdx === 0) {
      isDeleting = false;
      taglineIdx = (taglineIdx + 1) % TAGLINES.length;
    }
  }
  setTimeout(typewriterStep, isDeleting ? 40 : 65);
}

/* ========== PAGE TRANSITIONS ========== */
function enterDashboard() {
  const landing = document.getElementById('landing');
  const dashboard = document.getElementById('dashboard');

  landing.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
  landing.style.opacity = '0';
  landing.style.transform = 'scale(0.97)';

  setTimeout(() => {
    landing.classList.remove('active');
    landing.style.display = 'none';
    dashboard.classList.add('active');
    dashboard.style.opacity = '0';
    dashboard.style.transition = 'opacity 0.6s ease';

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        dashboard.style.opacity = '1';
        // Focus the password field
        document.getElementById('passwordInput').focus();
      });
    });
  }, 600);
}

function goBack() {
  const landing = document.getElementById('landing');
  const dashboard = document.getElementById('dashboard');

  dashboard.style.transition = 'opacity 0.4s ease';
  dashboard.style.opacity = '0';

  setTimeout(() => {
    dashboard.classList.remove('active');
    landing.classList.add('active');
    landing.style.display = '';
    landing.style.opacity = '0';
    landing.style.transform = 'scale(0.97)';
    landing.style.transition = 'opacity 0.5s ease, transform 0.5s ease';

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        landing.style.opacity = '1';
        landing.style.transform = 'scale(1)';
      });
    });
  }, 400);
}

/* ========== TAB SWITCHING ========== */
function switchTab(tabName, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  document.getElementById(`tab-${tabName}`).classList.add('active');
  btn.classList.add('active');
}

/* ========== TOGGLE PASSWORD VISIBILITY ========== */
function toggleVisibility() {
  const field = document.getElementById('passwordInput');
  const icon = document.getElementById('eyeIcon');

  if (field.type === 'password') {
    field.type = 'text';
    // Closed eye
    icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
  } else {
    field.type = 'password';
    icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  }
}

/* ========== REAL-TIME ANALYSIS ========== */
document.addEventListener('DOMContentLoaded', () => {
  typewriterStep();

  const input = document.getElementById('passwordInput');
  if (input) {
    input.addEventListener('input', (e) => {
      currentPassword = e.target.value;
      clearTimeout(analysisTimeout);

      if (!currentPassword) {
        resetUI();
        return;
      }

      // Debounce: analyze after 120ms of inactivity
      analysisTimeout = setTimeout(() => {
        analyzePassword(currentPassword);
      }, 120);
    });
  }
});

function resetUI() {
  // Reset all displays
  document.getElementById('metaLength').textContent = '0 chars';
  document.getElementById('metaEntropy').textContent = '0 bits entropy';
  document.getElementById('strengthLabel').textContent = '—';
  document.getElementById('strengthLabel').style.color = '';
  document.getElementById('strengthBar').style.width = '0%';
  document.getElementById('strengthBar').style.background = '';
  document.getElementById('scoreTotal').textContent = '0';
  document.getElementById('ringProgress').style.strokeDashoffset = '201';
  document.getElementById('ringProgress').style.stroke = 'var(--green)';
  document.getElementById('ct-casual').textContent = '—';
  document.getElementById('ct-gpu').textContent = '—';
  document.getElementById('ct-botnet').textContent = '—';
  document.getElementById('heatmapDisplay').innerHTML = '<span class="heatmap-idle">No password entered</span>';
  document.getElementById('feedbackList').innerHTML = '<div class="feedback-idle">Begin typing to receive threat intelligence...</div>';
  document.getElementById('threatModel').innerHTML = '<div class="threat-idle"><div class="threat-icon">⚡</div><p>Awaiting input...</p></div>';

  // Reset matrix
  ['lower','upper','digit','symbol'].forEach(k => {
    const el = document.getElementById(`m-${k}`);
    el.textContent = '—';
    el.className = 'matrix-val off';
  });
  document.getElementById('m-unique').textContent = '—';
  document.getElementById('m-length').textContent = '—';
  document.getElementById('m-charset').textContent = '—';
  document.getElementById('m-unique').className = 'matrix-val off';
  document.getElementById('m-length').className = 'matrix-val off';
  document.getElementById('m-charset').className = 'matrix-val off';

  // Reset score breakdown
  ['length','complexity','uniqueness','predictability','entropy'].forEach(k => {
    document.getElementById(`sb-${k}`).style.width = '0%';
    document.getElementById(`sv-${k}`).textContent = '0';
  });
}

async function analyzePassword(password) {
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password})
    });

    if (!response.ok) return;
    const data = await response.json();
    updateUI(data, password);

  } catch (err) {
    console.error('Analysis error:', err);
  }
}

function updateUI(data, password) {
  if (!data || !password) return;

  // Meta info
  document.getElementById('metaLength').textContent = `${data.password_length} chars`;
  document.getElementById('metaEntropy').textContent = `${data.entropy.bits} bits entropy`;

  // Strength label and bar
  const scoreVal = data.score.total;
  const strengthEl = document.getElementById('strengthLabel');
  strengthEl.textContent = data.strength.label;
  strengthEl.style.color = data.strength.color;
  strengthEl.style.textShadow = `0 0 10px ${data.strength.color}`;

  const bar = document.getElementById('strengthBar');
  bar.style.width = `${scoreVal}%`;

  if (scoreVal < 20) bar.style.background = 'linear-gradient(90deg, #ff0000, #ff4444)';
  else if (scoreVal < 40) bar.style.background = 'linear-gradient(90deg, #ff4444, #ff8800)';
  else if (scoreVal < 60) bar.style.background = 'linear-gradient(90deg, #ff8800, #ffcc00)';
  else if (scoreVal < 80) bar.style.background = 'linear-gradient(90deg, #ffcc00, #44ff44)';
  else bar.style.background = 'linear-gradient(90deg, #44ff44, #00ff88)';

  // Ring score
  document.getElementById('scoreTotal').textContent = scoreVal;
  const circumference = 201;
  const offset = circumference - (scoreVal / 100) * circumference;
  const ring = document.getElementById('ringProgress');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = scoreVal < 40 ? '#ff4444' : scoreVal < 60 ? '#ffcc00' : '#00ff41';
  ring.style.filter = `drop-shadow(0 0 6px ${ring.style.stroke})`;

  // Score breakdown
  const breakdown = data.score.breakdown;
  if (breakdown) {
    ['length','complexity','uniqueness','predictability','entropy'].forEach(k => {
      if (breakdown[k]) {
        const pct = (breakdown[k].score / breakdown[k].max) * 100;
        document.getElementById(`sb-${k}`).style.width = `${pct}%`;
        document.getElementById(`sv-${k}`).textContent = `${breakdown[k].score}/${breakdown[k].max}`;
      }
    });
  }

  // Crack times
  if (data.crack_times) {
    document.getElementById('ct-casual').textContent = data.crack_times.casual || '—';
    document.getElementById('ct-gpu').textContent = data.crack_times.gpu || '—';
    document.getElementById('ct-botnet').textContent = data.crack_times.botnet || '—';

    // Color code crack times
    colorCrackTime('ct-casual', data.crack_times.casual);
    colorCrackTime('ct-gpu', data.crack_times.gpu);
    colorCrackTime('ct-botnet', data.crack_times.botnet);
  }

  // Heatmap
  renderHeatmap(data.heatmap);

  // Feedback
  renderFeedback(data.feedback);

  // Character matrix (right panel)
  renderCharMatrix(data.char_analysis);

  // Threat model (left panel)
  renderThreatModel(data.patterns);

  // Terminal output
  addTerminalLines(data);
}

function colorCrackTime(elemId, timeStr) {
  if (!timeStr) return;
  const el = document.getElementById(elemId);
  const lowPriority = ['age of the universe', 'millennia', 'years'];
  const medium = ['months', 'days', 'hours'];
  const danger = ['minutes', 'seconds', 'instantly'];

  if (danger.some(d => timeStr.includes(d))) {
    el.style.color = 'var(--red)';
    el.style.textShadow = '0 0 8px var(--red)';
  } else if (medium.some(m => timeStr.includes(m))) {
    el.style.color = 'var(--yellow)';
    el.style.textShadow = '0 0 8px var(--yellow)';
  } else {
    el.style.color = 'var(--green)';
    el.style.textShadow = '0 0 8px var(--green)';
  }
}

function renderHeatmap(heatmap) {
  const display = document.getElementById('heatmapDisplay');
  if (!heatmap || !heatmap.length) {
    display.innerHTML = '<span class="heatmap-idle">No password entered</span>';
    return;
  }

  display.innerHTML = heatmap.map(item => {
    const reason = item.reason || '';
    return `<span class="heat-char ${item.heat}" data-reason="${reason}">${escapeHtml(item.char)}</span>`;
  }).join('');
}

function renderFeedback(feedback) {
  const list = document.getElementById('feedbackList');
  if (!feedback || !feedback.length) {
    list.innerHTML = '<div class="feedback-idle">Begin typing to receive threat intelligence...</div>';
    return;
  }

  list.innerHTML = feedback.map(f =>
    `<div class="feedback-item ${f.type}">
      <span>${f.icon}</span>
      <span>${escapeHtml(f.message)}</span>
    </div>`
  ).join('');
}

function renderCharMatrix(charData) {
  if (!charData) return;

  const lower = document.getElementById('m-lower');
  const upper = document.getElementById('m-upper');
  const digit = document.getElementById('m-digit');
  const symbol = document.getElementById('m-symbol');
  const unique = document.getElementById('m-unique');
  const length = document.getElementById('m-length');
  const charset = document.getElementById('m-charset');

  setMatrixVal(lower, charData.has_lowercase);
  setMatrixVal(upper, charData.has_uppercase);
  setMatrixVal(digit, charData.has_digits);
  setMatrixVal(symbol, charData.has_special);

  unique.textContent = charData.unique_chars;
  unique.className = 'matrix-val yes';
  length.textContent = currentPassword.length;
  length.className = 'matrix-val yes';
  charset.textContent = charData.charset_size;
  charset.className = 'matrix-val yes';
}

function setMatrixVal(el, isPresent) {
  el.textContent = isPresent ? '✓ YES' : '✗ NO';
  el.className = `matrix-val ${isPresent ? 'yes' : 'no'}`;
}

function renderThreatModel(patterns) {
  const container = document.getElementById('threatModel');
  if (!patterns || !patterns.length) {
    container.innerHTML = '<div class="threat-idle" style="color:var(--green);opacity:0.7"><div class="threat-icon">✓</div><p>No patterns detected</p></div>';
    return;
  }

  const icons = { critical: '☠', high: '⚠', medium: '→', low: 'ℹ' };
  container.innerHTML = patterns.map(p =>
    `<div class="threat-item ${p.severity}">
      <span class="t-icon">${icons[p.severity] || '•'}</span>
      <span>${escapeHtml(p.description)}</span>
    </div>`
  ).join('');
}

/* Terminal log */
function addTerminalLines(data) {
  const output = document.getElementById('terminalOutput');
  const now = new Date();
  const ts = now.toTimeString().slice(0,8);

  const newLines = [
    `> [${ts}] analyzing password...`,
    `> length: ${data.password_length} chars | charset: ${data.char_analysis?.charset_size || '?'}`,
    `> entropy: ${data.entropy.bits} bits (${data.entropy.rating})`,
    `> score: ${data.score.total}/100 — ${data.strength.label}`,
    `> patterns: ${data.patterns.length} detected`,
    `> crack estimate (GPU): ${data.crack_times?.gpu || '?'}`,
    `> analysis complete ✓`
  ];

  newLines.forEach(line => {
    const div = document.createElement('div');
    div.className = 't-line';

    if (line.includes('CRITICAL') || line.includes('instantly') || data.score.total < 30 && line.includes('score')) {
      div.className = 't-line danger';
    } else if (line.includes('complete')) {
      div.className = 't-line good';
    }

    div.textContent = line;
    output.appendChild(div);
  });

  // Keep last 40 lines
  while (output.children.length > 40) {
    output.removeChild(output.firstChild);
  }

  output.scrollTop = output.scrollHeight;
}

/* ========== BREACH CHECK ========== */
async function checkBreach() {
  if (!currentPassword) {
    showToast('Enter a password first');
    return;
  }

  const btn = document.getElementById('breachBtn');
  const panel = document.getElementById('breachResult');
  btn.textContent = 'CHECKING...';
  btn.disabled = true;

  panel.className = 'breach-panel idle';
  panel.innerHTML = '<div class="breach-icon">🔄</div><div class="breach-text loading-dots">Querying breach database</div>';

  try {
    const response = await fetch('/api/breach-check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: currentPassword})
    });

    const data = await response.json();

    if (data.breached === true) {
      panel.className = 'breach-panel danger';
      panel.innerHTML = `<div class="breach-icon">⚠</div><div class="breach-text">${escapeHtml(data.message)}</div>`;
    } else if (data.breached === false) {
      panel.className = 'breach-panel safe';
      panel.innerHTML = `<div class="breach-icon">✓</div><div class="breach-text">${escapeHtml(data.message)}</div>`;
    } else {
      panel.className = 'breach-panel idle';
      panel.innerHTML = `<div class="breach-icon">⚠</div><div class="breach-text">${escapeHtml(data.error || 'Check unavailable.')}</div>`;
    }
  } catch (err) {
    panel.className = 'breach-panel idle';
    panel.innerHTML = '<div class="breach-icon">✗</div><div class="breach-text">Network error. Check your connection.</div>';
  }

  btn.textContent = 'CHECK BREACH';
  btn.disabled = false;
}

/* ========== HACKER SIMULATION ========== */
const HACKER_SIM_LINES = [
  { text: '> initializing attack vectors...', delay: 0, cls: '' },
  { text: '> loading dictionary: rockyou.txt (14M entries)', delay: 400, cls: '' },
  { text: '> launching dictionary attack...', delay: 900, cls: '' },
  { text: '> no match in common passwords', delay: 1400, cls: 'good' },
  { text: '> scanning for keyboard patterns...', delay: 1800, cls: '' },
  { text: '> analyzing credential leak databases...', delay: 2300, cls: '' },
  { text: '> cross-referencing social media data (OSINT)...', delay: 2800, cls: '' },
  { text: '> applying rule-based mutations (l33t, append1234)...', delay: 3300, cls: '' },
  { text: '> pattern match probability calculated', delay: 3900, cls: '' },
  { text: '> initializing GPU brute-force...', delay: 4400, cls: 'warn' },
  { text: '> 10,245,887,332 combinations/sec', delay: 4900, cls: '' },
  { text: '> simulation complete. results above.', delay: 5500, cls: 'good' },
];

function runHackerSim() {
  if (hackerSimRunning) return;
  hackerSimRunning = true;

  const output = document.getElementById('hackerSimOutput');
  output.innerHTML = '';

  const score = document.getElementById('scoreTotal').textContent;
  const crackTime = document.getElementById('ct-gpu').textContent;

  let lines = [...HACKER_SIM_LINES];

  // Add dynamic result line based on actual analysis
  if (currentPassword) {
    lines.push({
      text: `> estimated compromise: ${crackTime || 'unknown'} (GPU)`,
      delay: 6000,
      cls: parseInt(score) < 50 ? 'danger' : 'good'
    });
  }

  lines.forEach(({ text, delay, cls }) => {
    setTimeout(() => {
      const div = document.createElement('div');
      div.className = `t-line ${cls}`;
      // Typing effect
      typeInto(div, text, () => {
        output.scrollTop = output.scrollHeight;
      });
      output.appendChild(div);
    }, delay);
  });

  setTimeout(() => {
    hackerSimRunning = false;
  }, 7000);
}

function typeInto(el, text, onDone) {
  let i = 0;
  const interval = setInterval(() => {
    el.textContent = text.substring(0, i + 1);
    i++;
    if (i >= text.length) {
      clearInterval(interval);
      if (onDone) onDone();
    }
  }, 18);
}

/* ========== PASSWORD GENERATOR ========== */
function updateLength(val) {
  document.getElementById('lengthVal').textContent = val;
}

async function generatePassword() {
  const length = parseInt(document.getElementById('lengthSlider').value);
  const symbols = document.getElementById('toggleSymbols').checked;
  const numbers = document.getElementById('toggleNumbers').checked;
  const uppercase = document.getElementById('toggleUpper').checked;
  const memorable = document.getElementById('toggleMemorable').checked;

  const display = document.getElementById('genPasswordDisplay');
  display.innerHTML = '<span class="gen-placeholder loading-dots">Generating</span>';

  try {
    const response = await fetch('/api/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ length, symbols, numbers, uppercase, memorable })
    });

    const data = await response.json();
    generatedPassword = data.password;

    display.innerHTML = '';
    // Type out the generated password
    const span = document.createElement('span');
    display.appendChild(span);
    typeInto(span, generatedPassword);

    // Show analysis
    if (data.analysis) {
      showGenAnalysis(data.analysis);
    }

  } catch (err) {
    display.innerHTML = '<span style="color:var(--red)">Generation failed. Try again.</span>';
  }
}

function showGenAnalysis(analysis) {
  const container = document.getElementById('genAnalysis');
  const content = document.getElementById('genAnalysisContent');
  container.style.display = 'block';

  content.innerHTML = `
    <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:0.72rem;line-height:2">
      <div>
        <span style="color:rgba(0,255,65,0.4)">Score: </span>
        <span style="color:var(--green);font-weight:bold">${analysis.score.total}/100</span>
      </div>
      <div>
        <span style="color:rgba(0,255,65,0.4)">Strength: </span>
        <span style="color:${analysis.strength.color}">${analysis.strength.label}</span>
      </div>
      <div>
        <span style="color:rgba(0,255,65,0.4)">Entropy: </span>
        <span style="color:var(--green)">${analysis.entropy.bits} bits</span>
      </div>
      <div>
        <span style="color:rgba(0,255,65,0.4)">GPU crack: </span>
        <span style="color:var(--green)">${analysis.crack_times?.gpu || '?'}</span>
      </div>
    </div>
  `;
}

function copyGenerated() {
  if (!generatedPassword) {
    showToast('Generate a password first');
    return;
  }
  navigator.clipboard.writeText(generatedPassword).then(() => {
    showToast('Password copied to clipboard');
  }).catch(() => {
    // Fallback
    const el = document.createElement('textarea');
    el.value = generatedPassword;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
    showToast('Password copied to clipboard');
  });
}

function useGenerated() {
  if (!generatedPassword) {
    showToast('Generate a password first');
    return;
  }
  // Switch to analyzer tab and populate
  const analyzerTab = document.querySelector('[data-tab="analyzer"]');
  switchTab('analyzer', analyzerTab);

  const field = document.getElementById('passwordInput');
  field.value = generatedPassword;
  currentPassword = generatedPassword;
  analyzePassword(generatedPassword);
  showToast('Password loaded into analyzer');
}

/* ========== TOAST ========== */
function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

/* ========== UTILS ========== */
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}