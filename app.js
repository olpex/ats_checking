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
// TECH ALIAS MAP — normalizes common variations
// --------------------------------------------------------
const TECH_ALIASES = {
  'js': 'javascript', 'ts': 'typescript', 'py': 'python',
  'reactjs': 'react', 'react.js': 'react', 'vuejs': 'vue', 'vue.js': 'vue',
  'angularjs': 'angular', 'angular.js': 'angular',
  'nodejs': 'node.js', 'node': 'node.js',
  'dotnet': '.net', 'net': '.net', 'netcore': '.net',
  'postgres': 'postgresql', 'postgre': 'postgresql',
  'mongo': 'mongodb', 'k8s': 'kubernetes',
  'ci/cd': 'ci cd', 'ci\\cd': 'ci cd',
  'aws': 'aws', 'gcp': 'gcp', 'azure': 'azure',
};

function normalizeTerm(term) {
  let t = term.toLowerCase().trim();
  if (TECH_ALIASES[t]) return TECH_ALIASES[t];
  // Strip trailing s for simple plurals (but not for "js", "css", etc.)
  if (t.length > 3 && t.endsWith('s') && !t.endsWith('ss') && !/^[a-z]{2}s$/.test(t)) {
    const stripped = t.slice(0, -1);
    if (TECH_ALIASES[stripped]) return TECH_ALIASES[stripped];
  }
  return t;
}

// --------------------------------------------------------
// TOKENIZER — preserves dots/hyphens in tech terms
// --------------------------------------------------------
function tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^a-zа-яёіїєґ0-9\s+#.\-]/gi, ' ')
    .split(/\s+/)
    .filter(w => w.length >= 2 && !STOP_WORDS.has(w));
}

// --------------------------------------------------------
// KEYWORD EXTRACTOR — signal-based, not frequency-based
// --------------------------------------------------------
function extractKeywords(text, topN = 40) {
  const rawTokens = tokenize(text);

  // Score each unique term by signal strength
  const termScores = {};

  for (const token of rawTokens) {
    const normalized = normalizeTerm(token);
    if (normalized.length < 2) continue;
    if (!termScores[normalized]) termScores[normalized] = { score: 0, original: token };

    let score = 1;
    // Bonus for technical patterns: contains dots, hyphens, or is a known acronym
    if (/[.\-]/.test(token) || /^[A-Z+#]+$/.test(token)) score += 3;
    // Bonus for capitalized terms in original (likely proper nouns/tech)
    if (/[A-Z]/.test(token) && token.length <= 20) score += 1;
    // Bonus for known tech terms
    if (TECH_ALIASES[token]) score += 2;

    termScores[normalized].score += score;
  }

  // Also extract 2-grams and 3-grams
  const words = text.toLowerCase().match(/[a-zа-яёіїєґ0-9+#.\-]{2,}/gi) || [];
  for (let ngram = 2; ngram <= 3; ngram++) {
    for (let i = 0; i <= words.length - ngram; i++) {
      const gramWords = words.slice(i, i + ngram);
      // Skip if any word is a stop word (except short tech terms)
      if (gramWords.some(w => STOP_WORDS.has(w) && !/^[a-z+#.]+$/.test(w))) continue;
      const phrase = gramWords.join(' ');
      if (phrase.length < 4 || phrase.length > 40) continue;
      const normalized = normalizeTerm(phrase);
      if (!termScores[normalized]) termScores[normalized] = { score: 0, original: phrase };
      termScores[normalized].score += ngram + 1; // 2-gram = 3pts, 3-gram = 4pts
    }
  }

  // Sort by score descending, take top N
  return Object.entries(termScores)
    .filter(([, v]) => v.score >= 1)
    .sort((a, b) => b[1].score - a[1].score)
    .slice(0, topN)
    .map(([k, v]) => ({ key: k, original: v.original, score: v.score }));
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
function keywordMatchesResume(keyword, resumeLower) {
  const kw = keyword.toLowerCase().trim();
  if (!kw || kw.length < 2) return false;

  // Exact word-boundary match
  const escaped = escapeRegex(kw);
  if (new RegExp(`\\b${escaped}\\b`, 'i').test(resumeLower)) return true;

  // Substring match for compound terms (e.g., "react" in "reactjs")
  if (kw.length >= 3 && resumeLower.includes(kw)) return true;

  // Check normalized aliases
  const normalized = normalizeTerm(kw);
  if (normalized !== kw) {
    const normEscaped = escapeRegex(normalized);
    if (new RegExp(`\\b${normEscaped}\\b`, 'i').test(resumeLower)) return true;
    if (normalized.length >= 3 && resumeLower.includes(normalized)) return true;
  }

  // Check alias expansion (e.g., "js" -> "javascript")
  for (const [alias, full] of Object.entries(TECH_ALIASES)) {
    if (alias === kw || full === kw) {
      const counterpart = alias === kw ? full : alias;
      const cpEscaped = escapeRegex(counterpart);
      if (new RegExp(`\\b${cpEscaped}\\b`, 'i').test(resumeLower)) return true;
    }
  }

  return false;
}

function scoreATS(resumeText, jobText) {
  const jdKeywords = extractKeywords(jobText, 40);
  const resumeLower = resumeText.toLowerCase();

  // Keyword matching
  const matched = [];
  const missing = [];
  for (const kw of jdKeywords) {
    if (keywordMatchesResume(kw.key, resumeLower) || keywordMatchesResume(kw.original, resumeLower)) {
      matched.push(kw.original);
    } else {
      missing.push(kw.original);
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
    .replace(/^Title:\s.*$/gmi, '')
    .replace(/^URL Source:\s.*$/gmi, '')
    .replace(/^Markdown Content:\s*$/gmi, '')
    .replace(/\s{3,}/g, '\n\n')  // collapse excess blank lines
    .replace(/\t/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/^\s+|\s+$/gm, '')
    .trim();
}

function normalizeJobUrlInput(rawInput) {
  const trimmed = (rawInput || '').trim();
  if (!trimmed) return '';
  // Allow pasting domains without protocol.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

function looksLikeHtml(content) {
  return /<(html|body|main|article|section|div|p)[\s>]/i.test(content);
}

function detectBlockedPage(content) {
  const text = String(content || '');
  const lower = text.toLowerCase();
  const signals = [
    { pattern: /captcha|recaptcha|hcaptcha|turnstile/i, label: 'CAPTCHA' },
    { pattern: /cloudflare.*challenge|cf-browser-verification|ray id/i, label: 'Cloudflare захист' },
    { pattern: /access denied|403 forbidden|forbidden|target url returned error 403/i, label: 'доступ заблоковано (403)' },
    { pattern: /please verify you are human|перевірте що ви не бот/i, label: 'перевірка бота' },
    { pattern: /checking your browser before|please wait while we check/i, label: 'перевірка браузера' },
    { pattern: /requiring captcha|maybe requiring captcha/i, label: 'потрібна CAPTCHA' },
    { pattern: /перевірка надійності підключення до сайту|перевірити безпеку вашого з.?єднання|перш ніж продовжити/i, label: 'перевірка безпеки з’єднання' },
  ];
  for (const s of signals) {
    if (s.pattern.test(text)) return s.label;
  }
  // Very short response that's not job content
  if (lower.length < 200 && /blocked|denied|error/.test(lower)) return 'відповідь заблокована';
  return null;
}

function extractJobText(rawContent) {
  if (!rawContent) return '';
  const source = String(rawContent).trim();
  if (!source) return '';
  if (looksLikeHtml(source)) return extractJobTextFromHtml(source);
  return cleanExtractedText(source);
}

function extractErrorMessage(err) {
  const msg = err && err.message ? err.message : String(err || 'unknown_error');
  if (msg.includes('Failed to fetch')) return 'мережевий запит заблоковано або недоступний';
  if (msg.includes('HTTP ')) return msg;
  return msg;
}

async function fetchJobContentWithStrategies(rawUrl) {
  const urlNoProtocol = rawUrl.replace(/^https?:\/\//i, '');
  let protectionDetected = false;
  const strategies = [
    {
      label: 'прямий запит',
      request: () => fetch(rawUrl, { signal: createTimeoutSignal(12000) }).then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      }),
    },
    {
      label: 'allorigins/raw',
      request: () => fetch(
        `https://api.allorigins.win/raw?url=${encodeURIComponent(rawUrl)}`,
        { signal: createTimeoutSignal(15000) }
      ).then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      }),
    },
    {
      label: 'allorigins/get',
      request: () => fetch(
        `https://api.allorigins.win/get?url=${encodeURIComponent(rawUrl)}`,
        { signal: createTimeoutSignal(15000) }
      ).then(async r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        return data && typeof data.contents === 'string' ? data.contents : '';
      }),
    },
    {
      label: 'r.jina.ai',
      request: () => fetch(
        `https://r.jina.ai/http://${urlNoProtocol}`,
        { signal: createTimeoutSignal(18000) }
      ).then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      }),
    },
  ];

  const errors = [];
  for (const strategy of strategies) {
    try {
      const payload = await strategy.request();
      const rawBlockReason = detectBlockedPage(payload);
      if (rawBlockReason) {
        protectionDetected = true;
        errors.push(`${strategy.label}: ${rawBlockReason}`);
        continue;
      }

      const extracted = extractJobText(payload);
      const extractedBlockReason = detectBlockedPage(extracted);
      if (extractedBlockReason) {
        protectionDetected = true;
        errors.push(`${strategy.label}: ${extractedBlockReason}`);
        continue;
      }

      if (countWords(extracted) >= 35) {
        return { extracted, strategy: strategy.label };
      }
      errors.push(`${strategy.label}: замало тексту після парсингу`);
    } catch (err) {
      errors.push(`${strategy.label}: ${extractErrorMessage(err)}`);
    }
  }

  if (protectionDetected) {
    throw new Error('Сайт повертає сторінку захисту (403/CAPTCHA). Для цього посилання вставте текст вакансії вручну в поле "Опис вакансії".');
  }

  throw new Error(`Не вдалося отримати текст вакансії. Спроби: ${errors.join(' | ')}`);
}

function extractJobTextFromHtml(html) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  // Try structured data first (many job pages expose JobPosting in JSON-LD)
  for (const script of doc.querySelectorAll('script[type="application/ld+json"]')) {
    try {
      const payload = JSON.parse(script.textContent || '{}');
      const entries = Array.isArray(payload) ? payload : [payload];
      for (const entry of entries) {
        const node = entry && entry['@graph'] ? entry['@graph'][0] : entry;
        if (!node || (node['@type'] && !String(node['@type']).toLowerCase().includes('jobposting'))) continue;
        const pieces = [
          node.title,
          node.description,
          node.responsibilities,
          node.qualifications,
          node.skills,
        ].filter(Boolean).join('\n\n');
        const cleaned = cleanExtractedText(String(pieces).replace(/<[^>]+>/g, ' '));
        if (cleaned.length > 180) return cleaned;
      }
    } catch {
      // Ignore malformed JSON-LD blocks.
    }
  }

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
const RESUME_SECTION_PATTERNS = [
  { key: 'summary', labels: ['summary', 'profile', 'objective', 'about me', 'про мене', 'профіль', 'резюме', 'мета', 'ціль', 'personal statement', 'career summary', 'professional summary'] },
  { key: 'experience', labels: ['experience', 'досвід', 'work history', 'work experience', 'employment', 'career', 'роботодавець', 'professional experience', 'professional background', 'історія роботи'] },
  { key: 'education', labels: ['education', 'освіта', 'academic', 'навчання', 'university', 'університет', 'academic background', 'qualifications', 'кваліфікації'] },
  { key: 'skills', labels: ['skills', 'навички', 'технології', 'tech stack', 'competencies', 'technologies', 'інструменти', 'tools', 'technical skills', 'hard skills'] },
  { key: 'other', labels: ['languages', 'мови', 'certif', 'сертиф', 'projects', 'проєкти', 'awards', 'volunteer', 'досягнення', 'achievements', 'interests', 'інтереси', 'publications', 'публікації'] },
];

function isContactLine(line) {
  return /@/.test(line) || /\+\d/.test(line) || /linkedin\.com/i.test(line) || /github\.com/i.test(line) || /(^|\s)\+?38\d{9}/.test(line) || /\d{3}[-.\s]\d{3}[-.\s]\d{4}/.test(line);
}

function isSectionHeading(line) {
  const cleaned = line.replace(/[:：\-–—=]+$/g, '').trim().toLowerCase();
  if (cleaned.length > 60) return null;
  for (const sec of RESUME_SECTION_PATTERNS) {
    for (const label of sec.labels) {
      if (cleaned === label || cleaned.startsWith(label + ' ') || cleaned.endsWith(' ' + label) || cleaned.includes(label + ':') || cleaned.includes(label + ' —')) {
        return sec.key;
      }
    }
  }
  // Heuristic: short ALL-CAPS or title-case lines that don't look like content
  if (line.length <= 40 && line === line.toUpperCase() && /^[A-ZА-ЯІЇЄҐ\s]+$/.test(line)) {
    const lower = line.toLowerCase().trim();
    for (const sec of RESUME_SECTION_PATTERNS) {
      for (const label of sec.labels) {
        if (lower.includes(label)) return sec.key;
      }
    }
  }
  return null;
}

function parseResumeSections(text) {
  const result = { name: '', contact: '', header: '', summary: '', experience: '', education: '', skills: '', other: '', raw: text };
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (!lines.length) return result;

  const firstSectionIndex = lines.findIndex(l => Boolean(isSectionHeading(l)));
  const topLines = firstSectionIndex >= 0
    ? lines.slice(0, firstSectionIndex)
    : lines.slice(0, Math.min(lines.length, 6));

  const nameSource = topLines.length ? topLines : lines;

  // Detect name — first non-contact, non-section line that looks like a name
  const nameLine = nameSource.find(l => {
    if (l.length < 2 || l.length > 60) return false;
    if (isContactLine(l)) return false;
    if (isSectionHeading(l)) return false;
    if (/^\d{4}/.test(l)) return false;
    if (/^[•\-\*]/.test(l)) return false;
    if (/http/i.test(l)) return false;
    return true;
  });
  if (nameLine) result.name = nameLine;

  // Collect contact lines (may be multiple)
  const contactLines = lines.filter(l => isContactLine(l));
  const contactLineSet = new Set(contactLines);
  result.contact = contactLines.join('  |  ');

  // Preserve original header lines from the top block (title, location, links, etc.)
  const headerLines = topLines.filter(l => l !== result.name && !contactLineSet.has(l) && !isSectionHeading(l));
  result.header = uniqueNonEmpty(headerLines).join('\n');

  // Parse sections
  let cur = null;
  const buckets = { summary: [], experience: [], education: [], skills: [], other: [] };

  for (const line of lines) {
    if (line === result.name) continue;
    if (contactLineSet.has(line)) continue;

    const sectionKey = isSectionHeading(line);
    if (sectionKey) { cur = sectionKey; continue; }
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
    /we are (?:looking for|hiring|seeking|searching for) (?:a |an )?(.{3,60})(?:\.|,|\n|$)/i,
    /(?:position|role|посада|вакансія|job title):?\s*(.{3,60})(?:\n|$)/i,
    /шукаємо\s+(.{3,60})(?:\n|,|\.|$)/i,
    /шукаємо\s+(?:сильного|досвідченого)?\s*(.{3,60})(?:\n|,|\.|$)/i,
    /hiring:?\s*(?:a |an )?(.{3,60})(?:\n|$)/i,
    /(?:seeking|looking for)\s+(?:a |an )?(.{3,60})(?:\n|\.|,|$)/i,
    /(?:join our team as|work as|become our)\s+(?:a |an )?(.{3,60})(?:\.|,|\n|$)/i,
    /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}(?:\s+(?:Developer|Engineer|Manager|Designer|Analyst|Architect|Lead|Specialist|Consultant|Director|Admin|Devops)))/m,
  ];
  for (const p of pats) {
    const m = jobText.match(p);
    if (m && m[1]) {
      const title = m[1].trim().replace(/[.\s]+$/, '');
      if (title.length >= 3 && title.length <= 60) return title;
    }
  }
  // Fallback: first line that looks like a job title
  const lines = jobText.split('\n').map(l => l.trim()).filter(l => l.length > 3);
  for (const line of lines) {
    if (line.length > 60) continue;
    if (/developer|engineer|manager|designer|analyst|architect|lead|specialist|consultant|devops|маркетолог|розробник|інженер|менеджер|дизайнер|аналітик/i.test(line)) {
      return line.replace(/[.\s]+$/, '');
    }
  }
  return lines[0] || 'Спеціаліст';
}

// --------------------------------------------------------
// HELPER — estimate years of experience
// --------------------------------------------------------
function detectYearsExp(rawText) {
  // Try explicit "X years of experience" first
  const m = rawText.match(/(\d+)\+?\s*(?:years?|роки?|років|рік)\s*(?:of\s*(?:experience|досвіду)|досвіду)?/i);
  if (m) return parseInt(m[1]);

  // Calculate from date ranges
  const dateRanges = rawText.match(/((?:19|20)\d{2})\s*[-–]\s*((?:19|20)\d{2}|present|current|нині|досі|сьогодні|today)/gi);
  if (dateRanges && dateRanges.length > 0) {
    const currentYear = new Date().getFullYear();
    let minStart = currentYear;
    let maxEnd = 0;
    for (const range of dateRanges) {
      const parts = range.split(/\s*[-–]\s*/);
      const start = parseInt(parts[0]);
      const endStr = parts[1].toLowerCase();
      const end = /present|current|нині|досі|сьогодні|today/.test(endStr) ? currentYear : parseInt(endStr);
      if (!isNaN(start) && start < minStart) minStart = start;
      if (!isNaN(end) && end > maxEnd) maxEnd = end;
    }
    if (maxEnd > minStart) return Math.min(maxEnd - minStart, 30);
  }

  // Count distinct date entries as fallback
  const yearEntries = (rawText.match(/\b(19|20)\d{2}\b/g) || []).length;
  return yearEntries >= 6 ? 5 : yearEntries >= 4 ? 3 : yearEntries >= 2 ? 2 : 1;
}

function uniqueNonEmpty(items) {
  const out = [];
  const seen = new Set();
  for (const item of items) {
    const v = String(item || '').trim();
    if (!v) continue;
    const k = v.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

// --------------------------------------------------------
// REWRITER — produces adapted resume object
// --------------------------------------------------------
function rewriteResume(parsed, matched, missing, jobText) {
  const jobTitle = detectJobTitle(jobText);
  const years = detectYearsExp(parsed.raw);
  const topMatched = uniqueNonEmpty(matched).slice(0, 8);
  const topMissing = uniqueNonEmpty(missing).slice(0, 6);

  // --- Summary ---
  // Preserve original summary as-is. Only add a short adaptation addendum.
  const baseSummary = (parsed.summary || '').trim();
  let newSummary = baseSummary;
  if (!newSummary) {
    newSummary = `Фахівець із ${years}+ роками досвіду. Цільова позиція: ${jobTitle}.`;
  } else {
    const addendum = [];
    if (!newSummary.toLowerCase().includes(jobTitle.toLowerCase())) {
      addendum.push(`Цільова позиція: ${jobTitle}.`);
    }
    if (topMatched.length > 0) {
      addendum.push(`Акцентувати в досвіді: ${topMatched.slice(0, 5).join(', ')}.`);
    }
    if (addendum.length > 0) {
      newSummary += `\n\n${addendum.join('\n')}`;
    }
  }

  // --- Skills ---
  // Keep original skills block and only append adaptation notes.
  const baseSkills = (parsed.skills || '').trim();
  const skillsAddendum = [];
  if (topMatched.length > 0) {
    skillsAddendum.push(`Релевантно до вакансії: ${topMatched.join(', ')}`);
  }
  if (topMissing.length > 0) {
    skillsAddendum.push(`Додати за наявності реального досвіду: ${topMissing.join(', ')}`);
  }
  const newSkills = baseSkills
    ? `${baseSkills}${skillsAddendum.length ? `\n\n${skillsAddendum.join('\n')}` : ''}`
    : (skillsAddendum.join('\n') || 'Додайте навички, релевантні до цільової позиції.');

  // --- Experience & Education: preserve original, don't dump raw ---
  const finalExperience = parsed.experience && parsed.experience.trim().length > 10
    ? parsed.experience.trim()
    : inferExperienceFromRaw(parsed.raw);

  const finalEducation = parsed.education && parsed.education.trim().length > 10
    ? parsed.education.trim()
    : inferEducationFromRaw(parsed.raw);

  const headerLines = uniqueNonEmpty((parsed.header || '').split('\n'));
  const contactParts = uniqueNonEmpty((parsed.contact || '').split('|').map(x => x.trim()));

  let finalName = (parsed.name || '').trim();
  const extraHeaderParts = [...headerLines];
  if (!finalName && extraHeaderParts.length > 0) {
    finalName = extraHeaderParts.shift();
  }
  const finalContact = uniqueNonEmpty([...extraHeaderParts, ...contactParts]).join('  |  ');

  return {
    name: finalName,
    contact: finalContact,
    summary: newSummary,
    skills: newSkills,
    experience: finalExperience,
    education: finalEducation,
    other: [parsed.other, topMissing.length ? `Порада: не додавайте технології без практичного досвіду, навіть якщо вони є в JD.` : '']
      .filter(Boolean)
      .join('\n\n'),
  };
}

// --------------------------------------------------------
// INFERENCE HELPERS — extract sections from raw text when headings missing
// --------------------------------------------------------
function inferExperienceFromRaw(rawText) {
  const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
  const experienceLines = [];
  let collecting = false;

  for (const line of lines) {
    // Detect experience-like content: date ranges, company-like patterns
    const hasDateRange = /\b(19|20)\d{2}\s*[-–]\s*((19|20)\d{2}|present|current|нині|досі)/i.test(line);
    const hasJobKeywords = /\b(developer|engineer|manager|analyst|designer|architect|lead|розробник|інженер|менеджер|аналітик|дизайнер|компанія|company|team|проєкт|project)\b/i.test(line);
    const hasBulletPoint = /^[•\-\*→]/.test(line);

    if (hasDateRange) collecting = true;
    if (collecting && (hasDateRange || hasJobKeywords || hasBulletPoint)) {
      experienceLines.push(line);
    }
    if (experienceLines.length >= 20) break;
  }

  if (experienceLines.length > 0) return experienceLines.join('\n');
  return '';
}

function inferEducationFromRaw(rawText) {
  const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
  const eduLines = [];

  for (const line of lines) {
    if (/(університет|university|college|інститут|institute|академія|academy|бакалавр|магістр|bachelor|master|phd|degree|диплом|КПІ|КНУ|ЛНУ|ХНУ|ОНУ|НаУКМА|освіта|education)/i.test(line)) {
      eduLines.push(line);
    }
    if (eduLines.length >= 10) break;
  }

  if (eduLines.length > 0) return eduLines.join('\n');
  return '';
}

// --------------------------------------------------------
// RENDER ADAPTED RESUME PREVIEW (HTML)
// --------------------------------------------------------
function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function formatBodyAsHtml(text) {
  if (!text) return '';
  const lines = text.split('\n');
  let html = '';
  let inList = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      if (inList) { html += '</ul>'; inList = false; }
      continue;
    }
    const isBullet = /^[•\-\*→▹▸▪●]\s*/.test(trimmed);
    if (isBullet) {
      if (!inList) { html += '<ul class="rp-list">'; inList = true; }
      html += `<li>${esc(trimmed.replace(/^[•\-\*→▹▸▪●]\s*/, ''))}</li>`;
    } else {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<p class="rp-line">${esc(trimmed)}</p>`;
    }
  }
  if (inList) html += '</ul>';
  return html;
}

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
    if (!s.body || !s.body.trim()) continue;
    html += `<div class="rp-section">
      <div class="rp-section-title">${s.icon} ${s.title}</div>
      <div class="rp-section-body">${formatBodyAsHtml(s.body)}</div>
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
    else await exportPDF(_latestAdapted);
  } catch (e) {
    console.error('[ATSAnalyzer] Export error:', e);
    const reason = e && e.message ? e.message : 'Невідома помилка';
    btn.textContent = '❌ Помилка експорту';
    alert(`Не вдалося сформувати файл (${fmt.toUpperCase()}).\n${reason}\n\nСпробуйте формат DOCX.`);
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
    children: [new TextRun({
      text,
      bold: true,
      size: lvl === 'title' ? 36 : 24,
      color: lvl === 'title' ? '1e0050' : '6366f1',
      font: 'Calibri',
    })],
    alignment: lvl === 'title' ? AlignmentType.CENTER : AlignmentType.LEFT,
    spacing: { before: lvl === 'title' ? 0 : 240, after: 60 },
    border: lvl === 'h2' ? {
      bottom: { style: BorderStyle.SINGLE, size: 4, color: '6366f1' }
    } : undefined,
  });

  const bodyParagraphs = (text) => {
    const lines = text.split('\n');
    const result = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const isBullet = /^[•\-\*→▹▸▪●]\s*/.test(trimmed);
      const cleanText = isBullet ? trimmed.replace(/^[•\-\*→▹▸▪●]\s*/, '') : trimmed;
      result.push(new Paragraph({
        children: [new TextRun({ text: cleanText, size: 20, font: 'Calibri' })],
        spacing: { after: isBullet ? 20 : 40 },
        bullet: isBullet ? { level: 0 } : undefined,
      }));
    }
    return result;
  };

  // Name
  if (adapted.name) children.push(heading(adapted.name, 'title'));

  // Contact
  if (adapted.contact) children.push(new Paragraph({
    children: [new TextRun({ text: adapted.contact, color: '555577', size: 18, font: 'Calibri' })],
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
    children.push(...bodyParagraphs(sec.text));
  }

  const doc = new Document({ sections: [{ children }] });
  const blob = await Packer.toBlob(doc);
  triggerDownload(blob, 'adapted_resume.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
}

// --------------------------------------------------------
// PDF EXPORT (jsPDF)
// --------------------------------------------------------

let _pdfFontCache = null;
let _pdfFontLoadFailed = false;

function streamArrayBufferToBase64(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  const chunkSize = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    let binary = '';
    for (let j = 0; j < chunk.length; j++) {
      binary += String.fromCharCode(chunk[j]);
    }
    result += btoa(binary);
  }
  return result;
}

async function ensurePdfUnicodeFonts(doc) {
  if (_pdfFontLoadFailed) throw new Error('PDF_FONT_LOAD_FAILED');
  if (!_pdfFontCache) {
    const FONT_URL = 'https://cdn.jsdelivr.net/gh/google/fonts@main/ofl/notosans/NotoSans%5Bwdth%2Cwght%5D.ttf';
    try {
      const resp = await fetch(FONT_URL, { signal: AbortSignal.timeout(25000) });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const buf = await resp.arrayBuffer();
      const base64 = streamArrayBufferToBase64(buf);
      _pdfFontCache = { normal: base64, bold: base64 };
    } catch (e) {
      _pdfFontLoadFailed = true;
      console.warn('[ATSAnalyzer] PDF font load failed:', e.message);
      throw new Error('PDF_FONT_LOAD_FAILED');
    }
  }
  const fontList = typeof doc.getFontList === 'function' ? doc.getFontList() : {};
  if (!fontList.NotoSans) {
    doc.addFileToVFS('NotoSans.ttf', _pdfFontCache.normal);
    doc.addFont('NotoSans.ttf', 'NotoSans', 'normal');
    doc.addFont('NotoSans.ttf', 'NotoSans', 'bold');
  }
}

async function exportPDF(adapted) {
  const { jsPDF } = window.jspdf || {};
  if (!jsPDF) throw new Error('jsPDF не завантажено. Спробуйте формат DOCX.');
  const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'portrait' });
  const requiresUnicode = /[^\u0000-\u00ff]/.test(JSON.stringify(adapted));
  let fontFamily = 'helvetica';

  if (requiresUnicode) {
    try {
      await ensurePdfUnicodeFonts(doc);
      fontFamily = 'NotoSans';
    } catch (e) {
      console.warn('[ATSAnalyzer] Falling back to helvetica — Cyrillic will not render. Use DOCX for Ukrainian text.');
    }
  }

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
    doc.setFont(fontFamily, bold ? 'bold' : 'normal');
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
    doc.setFont(fontFamily, 'bold');
    doc.setTextColor(99, 102, 241);
    doc.text(title.toUpperCase(), ML, y);
    y += 2;
    doc.setDrawColor(99, 102, 241);
    doc.setLineWidth(0.35);
    doc.line(ML, y, PW - MR, y);
    y += 5;
    doc.setTextColor(40, 40, 50);
    doc.setFont(fontFamily, 'normal');
  }

  if (adapted.name) addLine(adapted.name, { size: 22, bold: true, align: 'center', color: [15, 10, 45], spacing: 3 });
  if (adapted.contact) addLine(adapted.contact, { size: 9, align: 'center', color: [110, 110, 140], spacing: 6 });

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
      const trimmed = line.trim();
      if (!trimmed) continue;
      const isBullet = /^[•\-\*→▹▸▪●]\s*/.test(trimmed);
      const cleanText = isBullet ? '• ' + trimmed.replace(/^[•\-\*→▹▸▪●]\s*/, '') : trimmed;
      addLine(cleanText, { size: 9.5, spacing: isBullet ? 2 : 3 });
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
