/* ============================================================
   ATS ANALYZER — CORE ENGINE
   ============================================================ */

'use strict';

// --------------------------------------------------------
// STOP WORDS (Ukrainian + English)
// --------------------------------------------------------
const STOP_WORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
  'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has',
  'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might',
  'shall', 'can', 'need', 'must', 'this', 'that', 'these', 'those', 'it', 'its',
  'we', 'you', 'they', 'he', 'she', 'our', 'your', 'their', 'his', 'her', 'which',
  'who', 'what', 'when', 'where', 'how', 'all', 'more', 'also', 'as', 'if', 'not',
  'any', 'other', 'some', 'than', 'then', 'so', 'such', 'up', 'out', 'about', 'into',
  'through', 'each', 'both', 'per', 'use', 'used', 'using', 'work', 'worked', 'working',
  'та', 'і', 'й', 'або', 'але', 'в', 'на', 'до', 'з', 'за', 'по', 'про', 'для', 'від',
  'що', 'як', 'це', 'який', 'яка', 'яке', 'які', 'він', 'вона', 'вони', 'воно',
  'ми', 'ви', 'я', 'мій', 'моя', 'моє', 'наш', 'ваш', 'їх', 'його', 'її',
  'цей', 'ця', 'те', 'ці', 'той', 'та', 'те', 'не', 'ні', 'так', 'де', 'коли',
  'є', 'був', 'була', 'були', 'бути', 'мати', 'має', 'мав', 'мала', 'буде',
]);

// --------------------------------------------------------
// SECTION DEFINITIONS
// --------------------------------------------------------
const SECTIONS = [
  {
    key: 'contact',
    label: 'Контактна інформація',
    weight: 1,
    patterns: [
      /email|e-mail|телефон|phone|\+38|\d{3}[-.\s]\d{3}[-.\s]\d{4}|@\w+\.\w+/i,
      /linkedin|контакт|contacts?/i,
    ],
  },
  {
    key: 'summary',
    label: 'Профіль / Summary',
    weight: 1,
    patterns: [
      /\b(summary|profile|objective|about me|про мене|профіль|мета|ціль|резюме)\b/i,
    ],
  },
  {
    key: 'experience',
    label: 'Досвід роботи',
    weight: 2,
    patterns: [
      /\b(experience|досвід|work history|employment|роботодавець|worked at|позиція|посада)\b/i,
    ],
  },
  {
    key: 'education',
    label: 'Освіта',
    weight: 2,
    patterns: [
      /\b(education|освіта|university|університет|college|коледж|ступінь|degree|bachelor|master|bsc|msc|phd|диплом)\b/i,
    ],
  },
  {
    key: 'skills',
    label: 'Навички / Skills',
    weight: 2,
    patterns: [
      /\b(skills?|навички|технології|technologies|competencies|tools?|stack|інструменти)\b/i,
    ],
  },
  {
    key: 'languages',
    label: 'Мови',
    weight: 1,
    patterns: [
      /\b(languages?|мови|english|ukrainian|deutsch|french|spanish|fluent|native|upper)\b/i,
    ],
  },
  {
    key: 'projects',
    label: 'Проєкти / Projects',
    weight: 1,
    patterns: [
      /\b(projects?|проєкти|portfolio|pet project|opensource|open-source|github)\b/i,
    ],
  },
  {
    key: 'certifications',
    label: 'Сертифікати',
    weight: 1,
    patterns: [
      /\b(certif|сертифік|aws|gcp|azure|pmp|scrum|cisco|comptia|udemy|coursera)\b/i,
    ],
  },
];

// --------------------------------------------------------
// FORMATTING RISK PATTERNS
// --------------------------------------------------------
const FORMAT_RISKS = [
  { pattern: /\|.{1,40}\|/, msg: 'Виявлено символи таблиці', severity: 'high' },
  { pattern: /\t{2,}/, msg: 'Множинні табуляції — можлива колонкова верстка', severity: 'medium' },
  { pattern: /_{5,}/, msg: 'Лінійні роздільники можуть збити парсер', severity: 'low' },
];

// --------------------------------------------------------
// TOKENIZER
// --------------------------------------------------------
function tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^a-zа-яёіїєґ0-9\s+#.]/gi, ' ')
    .split(/\s+/)
    .filter(w => w.length >= 2 && !STOP_WORDS.has(w));
}

// --------------------------------------------------------
// KEYWORD EXTRACTOR (frequency-based, JD-weighted)
// --------------------------------------------------------
function extractKeywords(text, topN = 60) {
  const tokens = tokenize(text);
  const freq = {};
  for (const t of tokens) {
    freq[t] = (freq[t] || 0) + 1;
  }

  // Also include 2-grams for compound terms (e.g., "machine learning")
  const words = text.toLowerCase().match(/[a-zа-яёіїєґ0-9+#.]{2,}/gi) || [];
  for (let i = 0; i < words.length - 1; i++) {
    const bigram = `${words[i]} ${words[i + 1]}`;
    if (!STOP_WORDS.has(words[i]) && !STOP_WORDS.has(words[i + 1]) && words[i].length > 2 && words[i + 1].length > 2) {
      freq[bigram] = (freq[bigram] || 0) + 1;
    }
  }

  return Object.entries(freq)
    .filter(([k, v]) => v >= 1 && k.length >= 2)
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([k]) => k);
}

// --------------------------------------------------------
// SECTION DETECTOR
// --------------------------------------------------------
function detectSections(resumeText) {
  return SECTIONS.map(sec => {
    const found = sec.patterns.some(pat => pat.test(resumeText));
    return { ...sec, found };
  });
}

// --------------------------------------------------------
// FORMAT CHECKER
// --------------------------------------------------------
function checkFormat(resumeText) {
  const issues = [];
  for (const risk of FORMAT_RISKS) {
    risk.pattern.lastIndex = 0;
    if (risk.pattern.test(resumeText)) {
      issues.push({ msg: risk.msg, severity: risk.severity });
    }
  }
  return issues;
}

// --------------------------------------------------------
// MAIN ATS SCORER
// Returns { score, kwScore, secScore, fmtScore, matched, missing, sections, formatIssues }
// --------------------------------------------------------
function scoreATS(resumeText, jobText) {
  const jdKeywords = extractKeywords(jobText, 60);
  const resumeLower = resumeText.toLowerCase();

  // Keyword matching (case + partial)
  const matched = [];
  const missing = [];
  for (const kw of jdKeywords) {
    const pat = new RegExp(`\\b${escapeRegex(kw)}`, 'i');
    if (pat.test(resumeLower)) {
      matched.push(kw);
    } else {
      missing.push(kw);
    }
  }

  const kwScore = jdKeywords.length > 0
    ? Math.round((matched.length / jdKeywords.length) * 100)
    : 0;

  // Section detection
  const sections = detectSections(resumeText);
  const secTotal = sections.reduce((s, sec) => s + sec.weight, 0);
  const secFound = sections.filter(s => s.found).reduce((s, sec) => s + sec.weight, 0);
  const secScore = Math.round((secFound / secTotal) * 100);

  // Format
  const formatIssues = checkFormat(resumeText);
  const fmtPenalty = Math.min(formatIssues.reduce((s, i) => s + (i.severity === 'high' ? 20 : i.severity === 'medium' ? 10 : 5), 0), 30);
  const fmtScore = Math.max(100 - fmtPenalty, 30);

  // Weighted final score
  const score = Math.round(kwScore * 0.50 + secScore * 0.30 + fmtScore * 0.20);

  return { score, kwScore, secScore, fmtScore, matched, missing, sections, formatIssues };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --------------------------------------------------------
// RECOMMENDATION ENGINE
// --------------------------------------------------------
function buildRecommendations({ score, kwScore, secScore, fmtScore, matched, missing, sections, formatIssues }) {
  const recs = [];

  if (kwScore < 40) {
    recs.push({
      priority: 'high',
      icon: '🔑',
      text: `<strong>Критично низький рівень ключових слів (${kwScore}%).</strong> Уважно прочитайте вакансію та додайте у резюме відсутні терміни: ${missing.slice(0, 6).join(', ')}.`,
    });
  } else if (kwScore < 65) {
    recs.push({
      priority: 'medium',
      icon: '🔑',
      text: `<strong>Ключові слова (${kwScore}%).</strong> Ще є відсутні терміни з вакансії: ${missing.slice(0, 5).join(', ')}.`,
    });
  } else {
    recs.push({
      priority: 'low',
      icon: '✅',
      text: `<strong>Хороший рівень ключових слів (${kwScore}%).</strong> Більшість важливих термінів присутня у резюме.`,
    });
  }

  const missingSections = sections.filter(s => !s.found && s.weight >= 2);
  if (missingSections.length > 0) {
    recs.push({
      priority: 'high',
      icon: '📋',
      text: `<strong>Відсутні важливі секції:</strong> ${missingSections.map(s => s.label).join(', ')}. ATS не зможе коректно розпізнати ваш досвід.`,
    });
  }

  const optionalMissing = sections.filter(s => !s.found && s.weight < 2);
  if (optionalMissing.length > 0) {
    recs.push({
      priority: 'medium',
      icon: '📝',
      text: `<strong>Рекомендовано додати секції:</strong> ${optionalMissing.map(s => s.label).join(', ')}.`,
    });
  }

  for (const issue of formatIssues) {
    recs.push({
      priority: issue.severity === 'high' ? 'high' : 'medium',
      icon: '⚠️',
      text: `<strong>Проблема форматування:</strong> ${issue.msg}. Спрощений формат покращує розпізнавання тексту ATS.`,
    });
  }

  if (secScore === 100) {
    recs.push({
      priority: 'low',
      icon: '🏆',
      text: `<strong>Структура резюме відмінна!</strong> Всі основні секції присутні та будуть правильно розпізнані.`,
    });
  }

  if (score >= 80) {
    recs.push({
      priority: 'low',
      icon: '🚀',
      text: `<strong>Загальний рейтинг відмінний (${score}%)!</strong> Ваше резюме має високі шанси пройти ATS-фільтр.`,
    });
  } else if (score < 50) {
    recs.push({
      priority: 'high',
      icon: '💬',
      text: `<strong>Порада:</strong> Адаптуйте резюме окремо під кожну вакансію — це найефективніший спосіб підвищити ATS-рейтинг.`,
    });
  }

  // Sort: high first, then medium, then low
  const order = { high: 0, medium: 1, low: 2 };
  return recs.sort((a, b) => order[a.priority] - order[b.priority]);
}

// --------------------------------------------------------
// SCORE LABEL
// --------------------------------------------------------
function getScoreLabel(score) {
  if (score >= 80) return '🟢 Відмінно';
  if (score >= 60) return '🟡 Добре';
  if (score >= 40) return '🟠 Потребує покращення';
  return '🔴 Низький рейтинг';
}

// --------------------------------------------------------
// UI HELPERS
// --------------------------------------------------------
function countWords(text) {
  return text.trim() ? text.trim().split(/\s+/).length : 0;
}

// Update word count
document.getElementById('resumeText').addEventListener('input', function () {
  document.getElementById('resumeCount').textContent = `${countWords(this.value)} слів`;
});
document.getElementById('jobText').addEventListener('input', function () {
  document.getElementById('jobCount').textContent = `${countWords(this.value)} слів`;
});

// --------------------------------------------------------
// FILE PARSER — PDF / DOCX / TXT
// --------------------------------------------------------
const resumeUploadZone = document.getElementById('resumeUploadZone');
const resumeFileInput = document.getElementById('resumeFile');
const resumeTextarea = document.getElementById('resumeText');

function escapeInlineHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Set PDF.js worker path once the lib is available
function initPdfWorker() {
  if (typeof pdfjsLib !== 'undefined') {
    pdfjsLib.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  }
}
window.addEventListener('load', initPdfWorker);

function setUploadSuccess(name) {
  resumeUploadZone.querySelector('.upload-content').innerHTML =
    `<span class="upload-icon">✅</span><span><strong>${escapeInlineHtml(name)}</strong> завантажено</span>`;
  const hint = document.getElementById('uploadHint');
  if (hint) hint.style.display = 'none';
}

function setUploadError(msg) {
  resumeUploadZone.querySelector('.upload-content').innerHTML =
    `<span class="upload-icon">❌</span><span>${escapeInlineHtml(msg)}</span>`;
}

function setUploadLoading(name) {
  resumeUploadZone.querySelector('.upload-content').innerHTML =
    `<span class="upload-icon">⏳</span><span>Читаємо <strong>${escapeInlineHtml(name)}</strong>...</span>`;
}

async function parsePdf(file) {
  initPdfWorker();
  const arrayBuffer = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  let text = '';
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const content = await page.getTextContent();
    text += content.items.map(item => item.str).join(' ') + '\n';
  }
  return text.trim();
}

async function parseDocx(file) {
  const arrayBuffer = await file.arrayBuffer();
  const result = await mammoth.extractRawText({ arrayBuffer });
  return result.value.trim();
}

function parseTxt(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsText(file, 'UTF-8');
  });
}

async function handleFileUpload(file) {
  if (!file) return;
  const name = file.name.toLowerCase();
  setUploadLoading(file.name);

  try {
    let text = '';
    if (name.endsWith('.pdf')) {
      if (typeof pdfjsLib === 'undefined') throw new Error('PDF.js не завантажено. Перевірте інтернет-з\'єднання.');
      text = await parsePdf(file);
    } else if (name.endsWith('.docx')) {
      if (typeof mammoth === 'undefined') throw new Error('Mammoth.js не завантажено. Перевірте інтернет-з\'єднання.');
      text = await parseDocx(file);
    } else {
      text = await parseTxt(file);
    }

    if (!text || text.length < 20) {
      throw new Error('Не вдалося витягти текст. Файл може бути захищений або містити лише зображення.');
    }

    resumeTextarea.value = text;
    document.getElementById('resumeCount').textContent = `${countWords(text)} слів`;
    setUploadSuccess(file.name);
  } catch (err) {
    setUploadError(err.message || 'Помилка читання файлу.');
    console.error('[ATSAnalyzer] File parse error:', err);
  }
}

// File input change
resumeFileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) handleFileUpload(file);
});

// Drag & drop
resumeUploadZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  resumeUploadZone.classList.add('drag-over');
});
resumeUploadZone.addEventListener('dragleave', () => resumeUploadZone.classList.remove('drag-over'));
resumeUploadZone.addEventListener('drop', (e) => {
  e.preventDefault();
  resumeUploadZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) {
    const n = file.name.toLowerCase();
    if (n.endsWith('.pdf') || n.endsWith('.docx') || n.endsWith('.txt')) {
      handleFileUpload(file);
    } else {
      setUploadError('Підтримуються лише: PDF, DOCX, TXT');
    }
  }
});

// --------------------------------------------------------
// JOB SOURCE TABS (Text / URL)
// --------------------------------------------------------
function switchJobSource(mode) {
  const urlPanel = document.getElementById('jobUrlPanel');
  const tabText = document.getElementById('srcTabText');
  const tabUrl = document.getElementById('srcTabUrl');

  if (mode === 'url') {
    urlPanel.style.display = 'block';
    tabUrl.classList.add('active');
    tabText.classList.remove('active');
    document.getElementById('jobUrlInput').focus();
  } else {
    urlPanel.style.display = 'none';
    tabText.classList.add('active');
    tabUrl.classList.remove('active');
  }
}

// --------------------------------------------------------
// URL FETCH FOR JOB DESCRIPTION
// --------------------------------------------------------

// Site-specific content selectors (tried in order)
const JOB_SITE_SELECTORS = [
  // LinkedIn
  '.description__text',
  '.show-more-less-html__markup',
  // DOU.ua
  '.b-typo.vacancy-section',
  '#job-description',
  // Work.ua
  '.card-description',
  '.vacancy-description',
  // Djinni.co
  '.job-description',
  '.profile-page-section',
  // Rabota.ua
  '.vacancy-description__text',
  // Generic fallbacks
  '[data-testid="job-description"]',
  'article',
  'main',
];

function cleanExtractedText(text) {
  return text
    .replace(/\s{3,}/g, '\n\n')  // collapse excess blank lines
    .replace(/\t/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/^\s+|\s+$/gm, '')
    .trim();
}

function extractJobTextFromHtml(html) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  // Remove noise elements
  for (const el of doc.querySelectorAll('script, style, nav, header, footer, iframe, noscript, .cookie-banner, [aria-hidden="true"]')) {
    el.remove();
  }

  // Try site-specific selectors first
  for (const sel of JOB_SITE_SELECTORS) {
    const el = doc.querySelector(sel);
    if (el && el.textContent.trim().length > 150) {
      return cleanExtractedText(el.textContent);
    }
  }

  // Fallback: pick the largest <div> or <section> with meaningful text
  const candidates = [...doc.querySelectorAll('div, section, article')].filter(el => {
    const t = el.textContent.trim();
    return t.length > 300 && t.length < 20000;
  });

  if (candidates.length) {
    // Sort by text length descending, take top candidate
    candidates.sort((a, b) => b.textContent.length - a.textContent.length);
    return cleanExtractedText(candidates[0].textContent);
  }

  // Last resort: full body text
  return cleanExtractedText(doc.body.textContent);
}

function createTimeoutSignal(timeoutMs) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return AbortSignal.timeout(timeoutMs);
  }

  const controller = new AbortController();
  setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

async function fetchJobFromUrl() {
  const input = document.getElementById('jobUrlInput');
  const statusEl = document.getElementById('fetchStatus');
  const btn = document.getElementById('fetchBtn');
  const btnText = document.getElementById('fetchBtnText');
  const jobTextarea = document.getElementById('jobText');

  const rawUrl = input.value.trim();

  // Basic validation
  if (!rawUrl) {
    statusEl.className = 'fetch-status error';
    statusEl.textContent = '⚠️ Введіть URL вакансії.';
    return;
  }
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('invalid');
  } catch {
    statusEl.className = 'fetch-status error';
    statusEl.textContent = '⚠️ Невірний URL. Він має починатися з https://';
    return;
  }

  // Loading state
  btn.disabled = true;
  btnText.textContent = '⏳ Завантаження...';
  statusEl.className = 'fetch-status loading';
  statusEl.textContent = `⏳ Запит до ${parsedUrl.hostname}...`;

  // CORS proxy — allorigins returns raw HTML
  const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(rawUrl)}`;

  try {
    const resp = await fetch(proxyUrl, { signal: createTimeoutSignal(15000) });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const html = await resp.text();
    const extracted = extractJobTextFromHtml(html);

    if (!extracted || extracted.length < 100) {
      throw new Error('Не вдалося витягнути текст вакансії. Спробуйте скопіювати текст зі сторінки вручну.');
    }

    jobTextarea.value = extracted;
    document.getElementById('jobCount').textContent = `${countWords(extracted)} слів`;

    statusEl.className = 'fetch-status success';
    statusEl.textContent = `✅ Завантажено з ${parsedUrl.hostname} · ${countWords(extracted)} слів`;

    // Auto-switch to text view so user can review
    switchJobSource('text');

  } catch (err) {
    let msg = err.message || 'Помилка мережі.';
    if (err.name === 'TimeoutError' || err.name === 'AbortError') msg = 'Час очікування вичерпано. Спробуйте ще раз або скопіюйте текст вручну.';
    if (msg.includes('fetch') || msg.includes('network')) msg = 'Помилка мережі. Перевірте інтернет-з\'єднання.';

    statusEl.className = 'fetch-status error';
    statusEl.textContent = `❌ ${msg}`;
    console.error('[ATSAnalyzer] Fetch error:', err);
  } finally {
    btn.disabled = false;
    btnText.textContent = 'Завантажити';
  }
}

// --------------------------------------------------------
// KEYWORD TABS
// --------------------------------------------------------
function switchTab(tab) {
  document.querySelectorAll('.kw-tab').forEach((t, i) => {
    t.classList.toggle('active', (i === 0 && tab === 'matched') || (i === 1 && tab === 'missing'));
  });
  document.getElementById('matchedPanel').classList.toggle('hidden', tab !== 'matched');
  document.getElementById('missingPanel').classList.toggle('hidden', tab !== 'missing');
}

// --------------------------------------------------------
// ANIMATE SCORE RING
// --------------------------------------------------------
function animateScore(targetScore) {
  const arc = document.getElementById('scoreArc');
  const numEl = document.getElementById('scoreNum');
  const circumference = 408;

  let current = 0;
  const duration = 1200;
  const startTime = performance.now();

  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out-cubic
    current = Math.round(eased * targetScore);

    numEl.textContent = current;
    const dashoffset = circumference - (circumference * current) / 100;
    arc.style.strokeDashoffset = dashoffset;

    // Color by score
    if (current >= 80) {
      arc.style.stroke = '#10b981';
    } else if (current >= 60) {
      arc.style.stroke = 'url(#scoreGrad)';
    } else if (current >= 40) {
      arc.style.stroke = '#f59e0b';
    } else {
      arc.style.stroke = '#ef4444';
    }

    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// --------------------------------------------------------
// RENDER RESULTS
// --------------------------------------------------------
function renderResults(result) {
  const { score, kwScore, secScore, fmtScore, matched, missing, sections } = result;

  // Show panel
  document.getElementById('resultsPlaceholder').style.display = 'none';
  const panel = document.getElementById('resultsPanel');
  panel.style.display = 'flex';

  // Score sub-label
  document.getElementById('scoreSub').textContent = getScoreLabel(score);

  // Animate ring
  setTimeout(() => animateScore(score), 100);

  // Breakdown bars
  const breakdownData = [
    { label: 'Ключові слова', val: kwScore, color: 'linear-gradient(90deg,#6366f1,#06b6d4)' },
    { label: 'Структура', val: secScore, color: 'linear-gradient(90deg,#8b5cf6,#6366f1)' },
    { label: 'Форматування', val: fmtScore, color: 'linear-gradient(90deg,#06b6d4,#10b981)' },
  ];
  document.getElementById('scoreBreakdown').innerHTML = breakdownData.map(b => `
    <div class="breakdown-row">
      <span style="min-width:100px;font-size:0.78rem">${b.label}</span>
      <div class="breakdown-bar-wrap">
        <div class="breakdown-bar" style="width:0%;background:${b.color}" data-target="${b.val}"></div>
      </div>
      <span class="breakdown-val">${b.val}%</span>
    </div>
  `).join('');
  setTimeout(() => {
    document.querySelectorAll('.breakdown-bar').forEach(bar => {
      bar.style.width = bar.dataset.target + '%';
    });
  }, 200);

  // Keywords
  const matchedTags = document.getElementById('matchedTags');
  const missingTags = document.getElementById('missingTags');
  matchedTags.innerHTML = matched.slice(0, 30).map((kw, i) =>
    `<span class="kw-tag matched" style="animation-delay:${i * 0.04}s">✓ ${kw}</span>`
  ).join('');
  missingTags.innerHTML = missing.slice(0, 30).map((kw, i) =>
    `<span class="kw-tag missing" style="animation-delay:${i * 0.04}s">✗ ${kw}</span>`
  ).join('');

  if (missing.length === 0) {
    missingTags.innerHTML = '<span style="color:var(--green);font-size:0.85rem">🎉 Всі ключові слова знайдено!</span>';
  }

  // Sections
  document.getElementById('sectionsList').innerHTML = sections.map(s => `
    <div class="section-row ${s.found ? 'found' : 'missing'}">
      <span class="section-status">${s.found ? '✅' : '❌'}</span>
      <span class="section-name">${s.label}</span>
      <span class="section-badge">${s.found ? 'Знайдено' : 'Відсутня'}</span>
    </div>
  `).join('');

  // Recommendations
  const recs = buildRecommendations(result);
  document.getElementById('recsList').innerHTML = recs.map((r, i) => `
    <div class="rec-item ${r.priority}" style="animation-delay:${i * 0.08}s">
      <span class="rec-icon">${r.icon}</span>
      <span class="rec-text">${r.text}</span>
    </div>
  `).join('');
}

// --------------------------------------------------------
// EXPORT / COPY REPORT
// --------------------------------------------------------
function copyReport() {
  const resumeText = document.getElementById('resumeText').value;
  const jobText = document.getElementById('jobText').value;

  if (!resumeText || !jobText) return;

  const result = scoreATS(resumeText, jobText);
  const { score, kwScore, secScore, fmtScore, matched, missing, sections } = result;

  const report = `
╔══════════════════════════════════════╗
   ATS ANALYZER — ЗВІТ АНАЛІЗУ
╚══════════════════════════════════════╝

📊 ЗАГАЛЬНИЙ ATS SCORE: ${score}% — ${getScoreLabel(score)}

BREAKDOWN:
  🔑 Ключові слова:  ${kwScore}%
  📋 Структура:      ${secScore}%
  📄 Форматування:   ${fmtScore}%

ЗНАЙДЕНІ КЛЮЧОВІ СЛОВА (${matched.length}):
${matched.join(' · ')}

ВІДСУТНІ КЛЮЧОВІ СЛОВА (${missing.length}):
${missing.join(' · ')}

СЕКЦІЇ РЕЗЮМЕ:
${sections.map(s => `  ${s.found ? '✅' : '❌'} ${s.label}`).join('\n')}

══════════════════════════════════════
Сгенеровано ATSAnalyzer
  `.trim();

  copyTextToClipboard(report).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.classList.add('copied');
    btn.textContent = '✅ Скопійовано!';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.textContent = '📋 Скопіювати звіт';
    }, 2500);
  }).catch(() => {
    const btn = document.getElementById('copyBtn');
    btn.textContent = '❌ Не вдалося скопіювати';
    setTimeout(() => {
      btn.textContent = '📋 Скопіювати звіт';
    }, 2500);
  });
}

function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }

  return new Promise((resolve, reject) => {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      ta.style.pointerEvents = 'none';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) resolve();
      else reject(new Error('copy_failed'));
    } catch (err) {
      reject(err);
    }
  });
}

// --------------------------------------------------------
// MAIN ANALYSIS RUNNER
// --------------------------------------------------------
function runAnalysis() {
  const resumeText = document.getElementById('resumeText').value.trim();
  const jobText = document.getElementById('jobText').value.trim();
  const errorEl = document.getElementById('errorMsg');
  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('analyzeBtnText');

  // Validation
  errorEl.classList.remove('show');
  if (!resumeText && !jobText) {
    errorEl.textContent = '⚠️ Будь ласка, заповніть обидва поля: текст резюме та опис вакансії.';
    errorEl.classList.add('show');
    return;
  }
  if (!resumeText) {
    errorEl.textContent = '⚠️ Вставте текст вашого резюме.';
    errorEl.classList.add('show');
    return;
  }
  if (!jobText) {
    errorEl.textContent = '⚠️ Вставте текст опису вакансії (Job Description).';
    errorEl.classList.add('show');
    return;
  }
  if (resumeText.split(/\s+/).length < 20) {
    errorEl.textContent = '⚠️ Текст резюме занадто короткий. Вставте повний текст (мінімум 20 слів).';
    errorEl.classList.add('show');
    return;
  }
  if (jobText.split(/\s+/).length < 15) {
    errorEl.textContent = '⚠️ Текст вакансії занадто короткий. Вставте повний опис посади.';
    errorEl.classList.add('show');
    return;
  }

  // Loading state
  btn.classList.add('loading');
  btnText.textContent = '⏳ Аналізуємо...';
  btn.disabled = true;

  // Simulate brief processing delay for UX
  setTimeout(() => {
    try {
      const result = scoreATS(resumeText, jobText);
      renderResults(result);

      // Scroll to results
      document.getElementById('resultsPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      errorEl.textContent = '❌ Виникла помилка під час аналізу. Спробуйте ще раз.';
      errorEl.classList.add('show');
    } finally {
      btn.classList.remove('loading');
      btnText.textContent = '⚡ Аналізувати ще раз';
      btn.disabled = false;
    }
  }, 600);
}

// --------------------------------------------------------
// THEME TOGGLE
// --------------------------------------------------------
const THEME_STORAGE_KEY = 'ats_theme';

function getStoredTheme() {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

function getPreferredTheme() {
  if (typeof window.matchMedia !== 'function') return 'dark';
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function setTheme(theme) {
  const resolved = theme === 'light' ? 'light' : 'dark';
  const isLight = resolved === 'light';

  document.documentElement.setAttribute('data-theme', resolved);

  const toggle = document.getElementById('themeToggle');
  const toggleIcon = document.getElementById('themeToggleIcon');
  const toggleText = document.getElementById('themeToggleText');

  if (toggle) toggle.setAttribute('aria-pressed', String(isLight));
  if (toggleIcon) toggleIcon.textContent = isLight ? '☀️' : '🌙';
  if (toggleText) toggleText.textContent = isLight ? 'Світла' : 'Темна';
}

function persistTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Ignore storage write errors (private mode, blocked storage).
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  setTheme(next);
  persistTheme(next);
}

function initThemeToggle() {
  const initialTheme = getStoredTheme() || getPreferredTheme();
  setTheme(initialTheme);

  if (typeof window.matchMedia !== 'function') return;
  const media = window.matchMedia('(prefers-color-scheme: light)');
  const handlePreferenceChange = (event) => {
    if (getStoredTheme()) return;
    setTheme(event.matches ? 'light' : 'dark');
  };

  if (typeof media.addEventListener === 'function') {
    media.addEventListener('change', handlePreferenceChange);
  } else if (typeof media.addListener === 'function') {
    media.addListener(handlePreferenceChange);
  }
}

initThemeToggle();

// --------------------------------------------------------
// NAV SCROLL EFFECT
// --------------------------------------------------------
window.addEventListener('scroll', () => {
  document.getElementById('nav').classList.toggle('scrolled', window.scrollY > 40);
});

// --------------------------------------------------------
// SCROLL REVEAL
// --------------------------------------------------------
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.classList.add('visible');
      revealObserver.unobserve(e.target);
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.info-card, .step-item, .tip-card, .input-block').forEach(el => {
  el.classList.add('reveal');
  revealObserver.observe(el);
});

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'Enter') runAnalysis();
});

// ============================================================
//  RESUME REWRITER ENGINE
// ============================================================

// --------------------------------------------------------
// SECTION PARSER — splits raw resume text into labelled blocks
// --------------------------------------------------------
function parseResumeSections(text) {
  const result = { name: '', contact: '', summary: '', experience: '', education: '', skills: '', other: '', raw: text };
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (!lines.length) return result;

  // Detect name — first short line without obvious contact indicators
  const nameLine = lines.find(l => l.length >= 2 && l.length <= 60 && !/@/.test(l) && !/^\+/.test(l) && !/^\d/.test(l) && !/http/i.test(l));
  if (nameLine) result.name = nameLine;

  // Collect contact lines
  const contactLines = lines.filter(l =>
    /@/.test(l) || /\+\d/.test(l) || /linkedin\.com/i.test(l) || /github\.com/i.test(l) || /\d[\s.-]\d{2,}/.test(l)
  );
  const contactLineSet = new Set(contactLines);
  result.contact = contactLines.join('  |  ');

  // Section heading matchers
  const SEC_PATTERNS = [
    { key: 'summary', pat: /^(summary|profile|objective|about me|про мене|профіль|мета|ціль)\b/i },
    { key: 'experience', pat: /^(experience|досвід|work (history|experience)|employment|career|роботодавець)\b/i },
    { key: 'education', pat: /^(education|освіта|academic|навчання|university|університет)\b/i },
    { key: 'skills', pat: /^(skills?|навички|технології|tech stack|competencies|technologies|інструменти)\b/i },
    { key: 'other', pat: /^(languages?|мови|certif|сертиф|projects?|проєкти|awards?|volunteer)\b/i },
  ];

  let cur = null;
  const buckets = { summary: [], experience: [], education: [], skills: [], other: [] };

  for (const line of lines) {
    if (line === result.name) continue;
    if (contactLineSet.has(line)) continue;
    const match = SEC_PATTERNS.find(p => p.pat.test(line));
    if (match) { cur = match.key; continue; }
    if (cur) buckets[cur].push(line);
  }

  result.summary = buckets.summary.join('\n');
  result.experience = buckets.experience.join('\n');
  result.education = buckets.education.join('\n');
  result.skills = buckets.skills.join('\n');
  result.other = buckets.other.join('\n');
  return result;
}

// --------------------------------------------------------
// HELPER — detect job title from JD text
// --------------------------------------------------------
function detectJobTitle(jobText) {
  const pats = [
    /we are (?:looking for|hiring|seeking) (?:a |an )?(.{4,55})(?:\.|,|\n)/i,
    /(?:position|role|посада|вакансія):?\s*(.{4,55})(?:\n|$)/i,
    /шукаємо\s+(.{4,55})(?:\n|,|$)/i,
    /hiring:?\s*(.{4,55})(?:\n|$)/i,
  ];
  for (const p of pats) {
    const m = jobText.match(p);
    if (m && m[1].trim().length > 3) return m[1].trim().replace(/\.$/, '');
  }
  // Fallback: first non-blank line
  const firstLine = jobText.split('\n').map(l => l.trim()).find(l => l.length > 3 && l.length < 60);
  return firstLine || 'Спеціаліст';
}

// --------------------------------------------------------
// HELPER — estimate years of experience
// --------------------------------------------------------
function detectYearsExp(rawText) {
  const m = rawText.match(/(\d+)\+?\s*(?:years?|роки?|рік)\s*(?:of\s*experience|досвіду)?/i);
  if (m) return parseInt(m[1]);
  const dates = (rawText.match(/\d{4}\s*[-–]\s*(?:\d{4}|present|current|нині|досі)/gi) || []).length;
  return dates >= 3 ? 5 : dates === 2 ? 3 : dates === 1 ? 1 : 2;
}

// --------------------------------------------------------
// REWRITER — produces adapted resume object
// --------------------------------------------------------
function rewriteResume(parsed, matched, missing, jobText) {
  const jobTitle = detectJobTitle(jobText);
  const years = detectYearsExp(parsed.raw);
  const level = years >= 5 ? 'Senior' : years >= 3 ? 'Middle' : 'Junior';
  const topMatched = matched.slice(0, 6);
  const topMissing = missing.slice(0, 5);

  // --- Summary ---
  let newSummary = parsed.summary;
  if (!newSummary || newSummary.length < 60) {
    newSummary =
      `${level}-спеціаліст з ${years}+ роками досвіду, що претендує на роль ${jobTitle}. ` +
      (topMatched.length > 0 ? `Підтверджені компетенції: ${topMatched.join(', ')}. ` : '') +
      'Орієнтований на результат, командну роботу та постійний професійний розвиток.';
  } else {
    // Prepend job-title alignment sentence
    newSummary = `${level}-спеціаліст, зацікавлений у ролі ${jobTitle}. ` + newSummary;
    if (newSummary.length > 500) newSummary = newSummary.slice(0, 497) + '...';
  }

  // --- Skills ---
  const origSkillTokens = parsed.skills
    .split(/[\n,•\-|\/]/)
    .map(s => s.trim())
    .filter(s => s.length > 1 && s.length < 45);

  const matchedSkills = topMatched;
  const restSkills = origSkillTokens.filter(s => !topMatched.some(m => m.toLowerCase() === s.toLowerCase()));
  let newSkills = '';
  if (matchedSkills.length > 0) newSkills += `✦ Ключові (з вакансії): ${matchedSkills.join(', ')}\n`;
  if (restSkills.length > 0) newSkills += `◦ Додаткові: ${restSkills.join(', ')}\n`;
  if (topMissing.length > 0) newSkills += `⚡ Рекомендовано додати: ${topMissing.join(', ')}`;
  newSkills = newSkills.trim();

  return {
    name: parsed.name || 'Ваше Ім\'я',
    contact: parsed.contact,
    summary: newSummary,
    skills: newSkills || parsed.skills,
    experience: parsed.experience,
    education: parsed.education,
    other: parsed.other,
  };
}

// --------------------------------------------------------
// RENDER ADAPTED RESUME PREVIEW (HTML)
// --------------------------------------------------------
function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function renderResumePreview(adapted) {
  const card = document.getElementById('adaptedResumeCard');
  const preview = document.getElementById('resumePreview');
  card.style.display = 'block';

  const secs = [
    { icon: '📋', title: 'Профіль / Summary', body: adapted.summary },
    { icon: '🔧', title: 'Навички / Skills', body: adapted.skills },
    { icon: '💼', title: 'Досвід роботи', body: adapted.experience },
    { icon: '🎓', title: 'Освіта', body: adapted.education },
    { icon: '📌', title: 'Додатково', body: adapted.other },
  ];

  let html = '';
  if (adapted.name) html += `<div class="rp-name">${esc(adapted.name)}</div>`;
  if (adapted.contact) html += `<div class="rp-contact">${esc(adapted.contact)}</div>`;

  for (const s of secs) {
    if (!s.body) continue;
    html += `<div class="rp-section">
      <div class="rp-section-title">${s.icon} ${s.title}</div>
      <div class="rp-section-body">${esc(s.body)}</div>
    </div>`;
  }
  preview.innerHTML = html;
}

// --------------------------------------------------------
// STORE latest adapted resume for export
// --------------------------------------------------------
let _latestAdapted = null;

// --------------------------------------------------------
// HOOK INTO renderResults — trigger rewrite automatically
// --------------------------------------------------------
const _origRenderResults = renderResults;
renderResults = function (result) {
  _origRenderResults(result);
  try {
    const resumeText = document.getElementById('resumeText').value;
    const jobText = document.getElementById('jobText').value;
    if (resumeText && jobText) {
      const parsed = parseResumeSections(resumeText);
      _latestAdapted = rewriteResume(parsed, result.matched, result.missing, jobText);
      renderResumePreview(_latestAdapted);
    }
  } catch (e) {
    console.error('[ATSAnalyzer] Rewrite error:', e);
  }
};

// --------------------------------------------------------
// DOWNLOAD DISPATCHER
// --------------------------------------------------------
async function downloadResume() {
  if (!_latestAdapted) return;
  const btn = document.getElementById('downloadBtn');
  const fmt = document.querySelector('input[name="exportFmt"]:checked')?.value || 'docx';

  btn.disabled = true;
  btn.textContent = '⏳ Генерація...';
  try {
    if (fmt === 'docx') await exportDOCX(_latestAdapted);
    else exportPDF(_latestAdapted);
  } catch (e) {
    console.error('[ATSAnalyzer] Export error:', e);
    btn.textContent = '❌ Помилка';
    setTimeout(() => { btn.textContent = '⬇ Завантажити резюме'; btn.disabled = false; }, 2500);
    return;
  }
  btn.textContent = '✅ Завантажено!';
  setTimeout(() => { btn.textContent = '⬇ Завантажити резюме'; btn.disabled = false; }, 2000);
}

// --------------------------------------------------------
// DOCX EXPORT (docx.js v7)
// --------------------------------------------------------
async function exportDOCX(adapted) {
  const { Document, Paragraph, TextRun, HeadingLevel, Packer, AlignmentType, BorderStyle } = docx;

  const children = [];

  const heading = (text, lvl) => new Paragraph({
    children: [new TextRun({ text, bold: true, size: lvl === 'title' ? 36 : 24, color: lvl === 'title' ? '1e0050' : '6366f1' })],
    alignment: lvl === 'title' ? AlignmentType.CENTER : AlignmentType.LEFT,
    spacing: { before: lvl === 'title' ? 0 : 240, after: 60 },
    border: lvl === 'h2' ? {
      bottom: { style: BorderStyle.SINGLE, size: 4, color: '6366f1' }
    } : undefined,
  });

  const body = (text) => text.split('\n').map(line =>
    new Paragraph({
      children: [new TextRun({ text: line, size: 20 })],
      spacing: { after: 40 },
    })
  );

  // Name
  if (adapted.name) children.push(heading(adapted.name, 'title'));

  // Contact
  if (adapted.contact) children.push(new Paragraph({
    children: [new TextRun({ text: adapted.contact, color: '555577', size: 18 })],
    alignment: AlignmentType.CENTER,
    spacing: { after: 120 },
  }));

  const sections = [
    { title: 'Профіль / Summary', text: adapted.summary },
    { title: 'Навички / Skills', text: adapted.skills },
    { title: 'Досвід роботи', text: adapted.experience },
    { title: 'Освіта', text: adapted.education },
    { title: 'Додатково', text: adapted.other },
  ];

  for (const sec of sections) {
    if (!sec.text) continue;
    children.push(heading(sec.title, 'h2'));
    children.push(...body(sec.text));
  }

  const doc = new Document({ sections: [{ children }] });
  const blob = await Packer.toBlob(doc);
  triggerDownload(blob, 'adapted_resume.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
}

// --------------------------------------------------------
// PDF EXPORT (jsPDF)
// --------------------------------------------------------
function exportPDF(adapted) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'portrait' });

  const ML = 18, MR = 18, MT = 18;
  const PW = doc.internal.pageSize.getWidth();
  const PH = doc.internal.pageSize.getHeight();
  const CW = PW - ML - MR;
  let y = MT;

  function checkPageBreak(needed = 10) {
    if (y + needed > PH - 15) { doc.addPage(); y = MT; }
  }

  function addLine(text, { size = 10, bold = false, color = [40, 40, 50], align = 'left', spacing = 4 } = {}) {
    doc.setFontSize(size);
    doc.setFont('helvetica', bold ? 'bold' : 'normal');
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(text || '', CW);
    const lineH = size * 0.38 + 1;
    checkPageBreak(lines.length * lineH + spacing);
    doc.text(lines, align === 'center' ? PW / 2 : ML, y, { align });
    y += lines.length * lineH + spacing;
  }

  function addSectionTitle(title) {
    checkPageBreak(18);
    y += 4;
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(99, 102, 241);
    doc.text(title.toUpperCase(), ML, y);
    y += 2;
    doc.setDrawColor(99, 102, 241);
    doc.setLineWidth(0.35);
    doc.line(ML, y, PW - MR, y);
    y += 5;
    doc.setTextColor(40, 40, 50);
    doc.setFont('helvetica', 'normal');
  }

  // Name
  if (adapted.name) addLine(adapted.name, { size: 22, bold: true, align: 'center', color: [15, 10, 45], spacing: 3 });
  // Contact
  if (adapted.contact) addLine(adapted.contact, { size: 9, align: 'center', color: [110, 110, 140], spacing: 6 });

  // Divider
  doc.setDrawColor(200, 200, 220);
  doc.setLineWidth(0.2);
  doc.line(ML, y, PW - MR, y);
  y += 6;

  const secs = [
    { title: 'Профіль / Summary', text: adapted.summary },
    { title: 'Навички / Skills', text: adapted.skills },
    { title: 'Досвід роботи', text: adapted.experience },
    { title: 'Освіта', text: adapted.education },
    { title: 'Додатково', text: adapted.other },
  ];

  for (const sec of secs) {
    if (!sec.text) continue;
    addSectionTitle(sec.title);
    for (const line of sec.text.split('\n')) {
      if (line.trim()) addLine(line, { size: 9.5, spacing: 3 });
    }
  }

  doc.save('adapted_resume.pdf');
}

// --------------------------------------------------------
// HELPER — trigger browser file download
// --------------------------------------------------------
function triggerDownload(blob, filename, mime) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
