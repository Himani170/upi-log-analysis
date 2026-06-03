// ════════════════════════════════════════════════════════
// UPI GUARD — app.js  (fixed: breach detail + URL pre-flags)
// ════════════════════════════════════════════════════════

// ── Clock
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

function setUPI(val) { document.getElementById('upiInput').value = val; }

// ════════════════════════════════════════════════════════
// UPI ANALYZER
// ════════════════════════════════════════════════════════
function analyzeUPI() {
  const upi = document.getElementById('upiInput').value.trim();
  if (!upi) { alert('Enter a UPI ID first'); return; }
  const btn = document.querySelector('.scan-btn');
  btn.textContent = 'SCANNING...'; btn.disabled = true;
  fetch('/check-upi', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ upi_id: upi })
  })
  .then(r => { if (!r.ok) throw new Error('Server error'); return r.json(); })
  .then(data => { showResult(data); addRecent(data); refreshPie(); })
  .catch(err => alert('Backend error — is Flask running? ' + err.message))
  .finally(() => { btn.textContent = 'SCAN'; btn.disabled = false; });
}

function showResult(data) {
  document.getElementById('resultBox').style.display = 'block';
  const verdict = document.getElementById('verdict');
  verdict.textContent = data.verdict;
  verdict.className   = 'verdict-text ' + data.verdict.toLowerCase();
  document.getElementById('score').textContent = data.score + ' / 100';
  const fill = document.getElementById('scoreFill');
  fill.style.width = data.score + '%';
  fill.className   = 'score-bar-fill ' + data.verdict.toLowerCase();
  document.getElementById('reasons').innerHTML = (data.reasons || [])
    .map(r => `<div class="reason-item"><span class="reason-bullet">›</span>${r}</div>`).join('');
}

function addRecent(data) {
  const list = document.getElementById('recentList');
  const nd = list.querySelector('.no-data'); if (nd) nd.remove();
  const item = document.createElement('div');
  item.className = 'recent-item';
  item.innerHTML = `<span class="recent-upi">${data.upi}</span>
    <span class="recent-badge ${data.verdict.toLowerCase()}">${data.verdict}</span>`;
  list.prepend(item);
  const items = list.querySelectorAll('.recent-item');
  if (items.length > 6) items[items.length - 1].remove();
}

function refreshPie() {
  const wrap = document.getElementById('pieWrap');
  const img  = document.getElementById('pieChart');
  if (wrap && img) { wrap.style.display = 'block'; img.src = '/static/pie.png?t=' + Date.now(); }
}

// ════════════════════════════════════════════════════════
// PASSWORD STRENGTH CHECKER
// ════════════════════════════════════════════════════════
const pwInput      = document.getElementById('pw-input');
const pwBar        = document.getElementById('pw-strength-fill');
const pwRating     = document.getElementById('pw-rating');
const pwEntropy    = document.getElementById('pw-entropy');
const pwPwned      = document.getElementById('pw-pwned');
const pwFeedback   = document.getElementById('pw-feedback');
const pwConsole    = document.getElementById('pw-console');
const pwBreachCard = document.getElementById('pw-breach-card');
const pwScanBtn    = document.getElementById('pw-scan-btn');
const pwToggle     = document.getElementById('pw-toggle');
// NEW — breach detail elements
const pwBreachDetail = document.getElementById('pw-breach-detail');
const pwBreachTip    = document.getElementById('pw-breach-tip');

let pwTimeout = null;

if (pwToggle && pwInput) {
  pwToggle.addEventListener('click', () => {
    pwInput.type         = pwInput.type === 'password' ? 'text' : 'password';
    pwToggle.textContent = pwInput.type === 'password' ? '👁' : '🙈';
  });
}

if (pwInput) {
  pwInput.addEventListener('input', () => {
    clearTimeout(pwTimeout);
    const pw = pwInput.value;
    if (!pw) {
      pwBar.style.width = '0%'; pwBar.style.background = '#ef4444';
      pwRating.textContent = 'Waiting for input…';
      pwEntropy.textContent = '—'; pwPwned.textContent = 'Not scanned';
      pwFeedback.innerHTML = '';
      pwBreachCard.classList.remove('breached');
      if (pwBreachDetail) pwBreachDetail.style.display = 'none';
      return;
    }
    pwTimeout = setTimeout(() => checkPassword(pw), 350);
  });
  pwInput.addEventListener('keydown', e => { if (e.key === 'Enter') checkPassword(pwInput.value); });
}

if (pwScanBtn) {
  pwScanBtn.addEventListener('click', () => { if (pwInput.value) checkPassword(pwInput.value); });
}

function pwLogLine(text) {
  if (!pwConsole) return;
  const line = document.createElement('div');
  line.className = 'pw-console-line'; line.textContent = text;
  pwConsole.appendChild(line);
  pwConsole.scrollTop = pwConsole.scrollHeight;
}

function checkPassword(password) {
  pwLogLine('[SCAN] Starting analysis…');
  fetch('/api/check-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  })
  .then(r => r.json())
  .then(data => {
    updatePasswordUI(data);
    pwLogLine(`[RESULT] Score=${data.score} Rating=${data.rating} Entropy=${data.entropy} bits`);
    if (data.pwned_count > 0)
      pwLogLine(`[ALERT] Password found in ${data.pwned_count.toLocaleString()} breach(es)! Change it NOW.`);
    else if (data.pwned_count === 0)
      pwLogLine('[OK] No breach match detected — password is clean.');
    else
      pwLogLine('[WARN] Could not reach HIBP API — check your internet.');
  })
  .catch(err => pwLogLine('[ERROR] Cannot contact server: ' + err.message));
}

function updatePasswordUI(data) {
  const { score, rating, entropy, pwned_count, feedback, breach_detail, breach_tip } = data;

  // Strength bar
  pwBar.style.width = ((score / 5) * 100) + '%';
  const colors = ['#ef4444','#ef4444','#f97316','#eab308','#22c55e','#22c55e'];
  const glows  = [
    '0 0 8px rgba(239,68,68,0.7)', '0 0 8px rgba(239,68,68,0.7)',
    '0 0 8px rgba(249,115,22,0.7)', '0 0 8px rgba(234,179,8,0.7)',
    '0 0 12px rgba(34,197,94,0.9)', '0 0 16px rgba(34,197,94,1)'
  ];
  pwBar.style.background  = colors[score] || '#ef4444';
  pwBar.style.boxShadow   = glows[score]  || glows[0];
  pwRating.textContent    = rating;
  pwEntropy.textContent   = entropy + ' bits';

  // Breach status card
  if (pwned_count > 0) {
    pwPwned.textContent = `Breached (${pwned_count.toLocaleString()}×)`;
    pwBreachCard.classList.add('breached');
  } else if (pwned_count === 0) {
    pwPwned.textContent = '✓ No known breaches';
    pwBreachCard.classList.remove('breached');
  } else {
    pwPwned.textContent = 'API unreachable';
    pwBreachCard.classList.remove('breached');
  }

  // ── NEW: Show breach detail + tip below the cards ──
  if (pwBreachDetail) {
    if (breach_detail) {
      pwBreachDetail.style.display = 'block';
      pwBreachDetail.innerHTML = `
        <div class="breach-verdict ${pwned_count > 0 ? 'leaked' : 'safe'}" style="font-size:0.78rem;padding:8px 10px;margin-bottom:6px;">
          ${pwned_count > 0 ? '🚨' : '✅'} ${breach_detail}
        </div>
        ${breach_tip ? `<div class="breach-tip" style="font-size:0.72rem;">💡 ${breach_tip}</div>` : ''}
        ${pwned_count > 0 ? `<div style="margin-top:6px;font-size:0.72rem;opacity:0.7;">
          Check which sites: <a href="https://haveibeenpwned.com" target="_blank" style="color:#22c55e;">haveibeenpwned.com</a>
        </div>` : ''}
      `;
    } else {
      pwBreachDetail.style.display = 'none';
    }
  }

  // Feedback list
  pwFeedback.innerHTML = '';
  const msgs = (feedback && feedback.length)
    ? feedback
    : ['✓ Looks good! Use a unique password per site and consider a password manager.'];
  msgs.forEach(msg => {
    const li = document.createElement('li');
    li.textContent = msg;
    pwFeedback.appendChild(li);
  });
}

// ════════════════════════════════════════════════════════
// URL SCANNER — VirusTotal + our own pre-scan flags
// ════════════════════════════════════════════════════════
function scanURL() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { alert('Enter a URL or link to scan'); return; }
  const btn = document.getElementById('urlScanBtn');
  btn.textContent = 'SCANNING...'; btn.disabled = true;

  const box = document.getElementById('urlResult');
  box.style.display = 'block';
  document.getElementById('urlVerdict').textContent = '⏳ Scanning with 70+ antivirus engines... (10–15 sec)';
  document.getElementById('urlVerdict').className   = 'breach-verdict';
  document.getElementById('urlStats').innerHTML     = '';
  document.getElementById('urlTip').textContent     = '';
  const urlFlags = document.getElementById('urlFlags');
  if (urlFlags) urlFlags.innerHTML = '';

  fetch('/scan-url', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  })
  .then(r => r.json())
  .then(data => showURLResult(data))
  .catch(err => {
    document.getElementById('urlVerdict').textContent = '❌ Error: ' + err.message;
  })
  .finally(() => { btn.textContent = 'SCAN URL'; btn.disabled = false; });
}

function showURLResult(data) {
  document.getElementById('urlResult').style.display = 'block';

  const verdict = document.getElementById('urlVerdict');
  verdict.textContent = (data.safe === false ? '🚨 ' : data.safe === true ? '✅ ' : '⚠️ ') + data.message;
  verdict.className   = 'breach-verdict ' +
    (data.safe === false ? 'leaked' : data.safe === true ? 'safe' : '');

  // VT engine stats
  const stats = document.getElementById('urlStats');
  if (data.total > 0) {
    stats.innerHTML = `
      <span class="breach-site-tag" style="background:#c0392b">🔴 Malicious: ${data.malicious}</span>
      <span class="breach-site-tag" style="background:#e67e22">🟠 Suspicious: ${data.suspicious}</span>
      <span class="breach-site-tag" style="background:#27ae60">🟢 Clean: ${data.harmless}</span>
      <span class="breach-site-tag">Total engines: ${data.total}</span>
    `;
  } else {
    stats.innerHTML = '';
  }

  document.getElementById('urlTip').textContent = data.tip ? '💡 ' + data.tip : '';

  // ── NEW: Show our own pre-scan flags (IP, keywords, HTTP, index-of) ──
  const urlFlags = document.getElementById('urlFlags');
  if (urlFlags) {
    if (data.pre_flags && data.pre_flags.length) {
      urlFlags.style.display = 'block';
      urlFlags.innerHTML = `
        <div style="font-size:0.72rem;color:#9ca3af;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:5px;">
          OUR ANALYSIS FLAGS
        </div>
        ${data.pre_flags.map(f => `
          <div class="reason-item" style="font-size:0.75rem;margin-bottom:4px;">
            <span class="reason-bullet">›</span>${f}
          </div>`).join('')}
      `;
    } else {
      urlFlags.style.display = 'none';
    }
  }
}

// Enter key support
document.addEventListener('DOMContentLoaded', () => {
  const upiIn = document.getElementById('upiInput');
  if (upiIn) upiIn.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeUPI(); });
  const urlIn = document.getElementById('urlInput');
  if (urlIn) urlIn.addEventListener('keydown', e => { if (e.key === 'Enter') scanURL(); });
});
