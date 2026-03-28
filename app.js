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
  { key: 'tables', pattern: /\|.{1,40}\|/, msg: 'Виявлено символи таблиці', severity: 'high' },
  { key: 'tabs', pattern: /\t{2,}/, msg: 'Множинні табуляції — можлива колонкова верстка', severity: 'medium' },
  { key: 'separators', pattern: /_{5,}/, msg: 'Лінійні роздільники можуть збити парсер', severity: 'low' },
  { key: 'links', pattern: /https?:\/\/\S+/i, msg: 'Надлишкова кількість посилань може зашумлювати резюме', severity: 'medium' },
  { key: 'longline', pattern: /.{220,}/, msg: 'Дуже довгі рядки ускладнюють парсинг і читання', severity: 'medium' },
  { key: 'graphic_noise', pattern: /\[!\[image|social-icons|cdn-cgi|company-logo/i, msg: 'Виявлено технічний шум із веб-сторінки', severity: 'high' },
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

function isNoiseKeyword(term) {
  const t = String(term || '').toLowerCase().trim();
  if (!t) return true;
  if (t.length > 45) return true;
  if (/^https?:\/\//.test(t) || t.includes('www.')) return true;
  if (/\b(?:com|ua|net|org|site|png|jpg|jpeg|svg|gif|webp)\b/.test(t) && t.includes('.')) return true;
  if (/social-icons|cdn-cgi|company-logo|image\s*\d+/i.test(t)) return true;
  if (/^\d+$/.test(t)) return true;
  if (/^[#./:_-]+$/.test(t)) return true;
  return false;
}

const NOISE_LINE_PATTERNS = [
  /^title:\s*/i,
  /^url source:\s*/i,
  /^markdown content:\s*$/i,
  /^сервіс пошуку роботи/i,
  /^резюме кандидата розміщено за адресою/i,
  /(?:^|\s)(до пошуку|відгукнутись)(?:\s|$)/i,
  /social-icons|cdn-cgi|company-logo|cf-rabota|image\s*\d+/i,
  /перевірка надійності підключення|перевірити безпеку вашого з.?єднання|перш ніж продовжити/i,
  /warning:\s*target url returned error 403/i,
];

function isResumeNoiseLine(line) {
  const t = String(line || '').trim();
  const lower = t.toLowerCase();
  if (!t) return true;
  if (NOISE_LINE_PATTERNS.some((pat) => pat.test(t))) return true;
  if (/^\[!\[image/i.test(lower)) return true;
  if (/^#\s*(robota\.ua|work\.ua|до пошуку|відгукнутись)/i.test(t)) return true;
  if (/^\*\*[^*]{1,80}\*\*$/.test(t) && /(?:робот|job|vacancy|ваканс)/i.test(t)) return true;
  if ((lower.match(/https?:\/\//g) || []).length >= 2) return true;
  if ((t.match(/\b(?:png|jpg|jpeg|svg|webp)\b/gi) || []).length >= 2) return true;
  return false;
}

function sanitizeSectionText(text, maxLines = 80) {
  return String(text || '')
    .replace(/(місяц[івя]\)|рок[иів]\)|нині\)|досі\))(?=[A-ZА-ЯІЇЄҐ])/g, '$1\n')
    .replace(/(https?:\/\/\S+)(?=[A-ZА-ЯІЇЄҐ])/g, '$1\n')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .filter(l => !isResumeNoiseLine(l))
    .slice(0, maxLines)
    .join('\n')
    .trim();
}

function sanitizeResumeSource(text) {
  return String(text || '')
    .replace(/\r/g, '')
    .replace(/\[!\[.*?\]\(.*?\)\]/g, ' ')
    .replace(/\[(.*?)\]\((https?:\/\/.*?)\)/g, '$1')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .filter(l => !isResumeNoiseLine(l))
    .join('\n')
    .trim();
}

function sanitizeJobSource(text) {
  return cleanExtractedText(String(text || ''))
    .replace(/\[!\[.*?\]\(.*?\)\]/g, ' ')
    .replace(/\[(.*?)\]\((https?:\/\/.*?)\)/g, '$1')
    .replace(/(?:^|\n)\s*#+\s*/g, '\n')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .filter(l => !isResumeNoiseLine(l))
    .filter(l => !/^(share|apply|відгук|поділитись|опубліковано|published)\b/i.test(l))
    .slice(0, 260)
    .join('\n')
    .trim();
}

const ACTION_VERBS = [
  'implemented', 'designed', 'built', 'optimized', 'led', 'managed', 'delivered', 'created',
  'developed', 'improved', 'automated', 'deployed', 'migrated', 'configured', 'maintained',
  'впровадив', 'впровадила', 'створив', 'створила', 'оптимізував', 'оптимізувала', 'налаштував',
  'налаштувала', 'розробив', 'розробила', 'керував', 'керувала', 'покращив', 'покращила',
];

const METRIC_PATTERN = /\b\d+(?:[.,]\d+)?\s*(?:%|процент|відсотк|ms|sec|seconds|год|годин|тиж|місяц|рок|users?|користувач|клієнт|проєкт|projects?)\b/i;

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
    if (isNoiseKeyword(token)) continue;
    const normalized = normalizeTerm(token);
    if (isNoiseKeyword(normalized)) continue;
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
      if (isNoiseKeyword(phrase)) continue;
      const normalized = normalizeTerm(phrase);
      if (isNoiseKeyword(normalized)) continue;
      if (!termScores[normalized]) termScores[normalized] = { score: 0, original: phrase };
      termScores[normalized].score += ngram + 1; // 2-gram = 3pts, 3-gram = 4pts
    }
  }

  // Sort by score descending, take top N
  return Object.entries(termScores)
    .filter(([k, v]) => v.score >= 1 && !isNoiseKeyword(k) && !isNoiseKeyword(v.original))
    .sort((a, b) => b[1].score - a[1].score)
    .slice(0, topN)
    .map(([k, v]) => ({ key: k, original: v.original, score: v.score }));
}

// --------------------------------------------------------
// SECTION DETECTOR
// --------------------------------------------------------
const SECTION_INSERT_TEMPLATES = {
  contact: 'Контактна інформація\nТелефон: +380\nEmail: your@email.com\nLinkedIn: linkedin.com/in/username\nМісто: Київ',
  summary: 'Профіль / Summary\nКороткий професійний профіль (3-5 речень): роль, стек, роки досвіду, ключова цінність.',
  experience: 'Досвід роботи\nНазва посади — Компанія\n01.2023 - нині\n• Виконав(ла) ...\n• Оптимізував(ла) ... на X%',
  education: 'Освіта\nНазва закладу — Спеціальність\n2018 - 2022',
  skills: 'Навички / Skills\n• Skill 1\n• Skill 2\n• Skill 3',
  languages: 'Мови\nУкраїнська — вільно\nАнглійська — Upper-Intermediate',
  projects: 'Проєкти / Projects\nНазва проєкту\n• Короткий опис ролі та результату',
  certifications: 'Сертифікати\nНазва сертифікату — Організація, Рік',
};

function evaluateSectionQuality(sectionKey, text) {
  const words = countWords(text || '');
  const lines = String(text || '').split('\n').map(l => l.trim()).filter(Boolean).length;
  const thresholds = {
    contact: { weakWords: 2, goodWords: 6 },
    summary: { weakWords: 10, goodWords: 30 },
    experience: { weakWords: 25, goodWords: 80 },
    education: { weakWords: 8, goodWords: 20 },
    skills: { weakWords: 8, goodWords: 20 },
    languages: { weakWords: 2, goodWords: 6 },
    projects: { weakWords: 10, goodWords: 25 },
    certifications: { weakWords: 4, goodWords: 12 },
  };
  const t = thresholds[sectionKey] || { weakWords: 8, goodWords: 20 };
  if (words < t.weakWords || lines === 0) return { quality: 'missing', words, lines };
  if (words < t.goodWords) return { quality: 'weak', words, lines };
  return { quality: 'good', words, lines };
}

function detectSections(resumeText) {
  const parsed = parseResumeSections(resumeText);
  const otherText = `${parsed.other || ''}\n${parsed.raw || ''}`.toLowerCase();
  const evidenceByKey = {
    contact: `${parsed.contact || ''}\n${parsed.header || ''}`.trim(),
    summary: parsed.summary || '',
    experience: parsed.experience || '',
    education: parsed.education || '',
    skills: parsed.skills || '',
    languages: (parsed.other || '').split('\n').filter(l => /\b(english|ukrainian|німец|deutsch|french|spanish|мова|мови)\b/i.test(l)).join('\n'),
    projects: (parsed.other || '').split('\n').filter(l => /\b(project|проєкт|portfolio|github|pet project)\b/i.test(l) || /https?:\/\//i.test(l)).join('\n'),
    certifications: parsed.certifications || (parsed.other || '').split('\n').filter(l => /\b(certif|сертиф|course|курс|azure|aws|gcp|cisco|comptia|coursera|udemy)\b/i.test(l)).join('\n'),
  };

  return SECTIONS.map(sec => {
    const localText = String(evidenceByKey[sec.key] || '');
    const contentCheck = evaluateSectionQuality(sec.key, localText);
    const patternFound = sec.patterns.some(pat => pat.test(localText) || pat.test(otherText));
    const found = contentCheck.quality !== 'missing' || patternFound;
    const quality = found ? (contentCheck.quality === 'missing' ? 'weak' : contentCheck.quality) : 'missing';

    let detail = 'Секція відсутня';
    if (found && quality === 'good') detail = `${contentCheck.words} слів, ${contentCheck.lines} рядків`;
    if (found && quality === 'weak') detail = `Секція знайдена, але заповнена слабо (${contentCheck.words} слів)`;

    return {
      ...sec,
      found,
      quality,
      words: contentCheck.words,
      lines: contentCheck.lines,
      detail,
    };
  });
}

function appendSectionTemplate(sectionKey) {
  const textarea = document.getElementById('resumeText');
  if (!textarea) return;
  const template = SECTION_INSERT_TEMPLATES[sectionKey];
  if (!template) return;

  const current = String(textarea.value || '').trim();
  const updated = current ? `${current}\n\n${template}` : template;
  textarea.value = updated;
  document.getElementById('resumeCount').textContent = `${countWords(updated)} слів`;
  textarea.focus();
  textarea.setSelectionRange(updated.length, updated.length);

  // Re-run analysis immediately so section diagnostics become interactive.
  const jobText = String(document.getElementById('jobText')?.value || '').trim();
  if (jobText) runAnalysis();
}

window.appendSectionTemplate = appendSectionTemplate;

// --------------------------------------------------------
// FORMAT CHECKER
// --------------------------------------------------------
function checkFormat(resumeText) {
  const issues = [];
  for (const risk of FORMAT_RISKS) {
    risk.pattern.lastIndex = 0;
    if (risk.pattern.test(resumeText)) {
      issues.push({ key: risk.key, msg: risk.msg, severity: risk.severity });
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

function splitResumeZones(resumeText) {
  const parsed = parseResumeSections(resumeText);
  return {
    summary: (parsed.summary || '').toLowerCase(),
    skills: (parsed.skills || '').toLowerCase(),
    experience: (parsed.experience || '').toLowerCase(),
    education: (parsed.education || '').toLowerCase(),
    other: (parsed.other || '').toLowerCase(),
  };
}

function countKeywordHitsByZone(keyword, zones) {
  const kw = keyword.toLowerCase();
  const has = (src) => keywordMatchesResume(kw, src);
  return {
    summary: has(zones.summary),
    skills: has(zones.skills),
    experience: has(zones.experience),
    education: has(zones.education),
    other: has(zones.other),
  };
}

function computeContextScore(matched, resumeText, zones) {
  if (!matched.length) return 0;
  const lower = resumeText.toLowerCase();
  const lines = resumeText.split('\n').map(l => l.trim()).filter(Boolean);
  let scoreSum = 0;

  for (const kw of matched) {
    const hit = countKeywordHitsByZone(kw, zones);
    let zoneWeight = 0;
    if (hit.summary) zoneWeight += 1.25;
    if (hit.experience) zoneWeight += 1.15;
    if (hit.skills) zoneWeight += 1.0;
    if (hit.education) zoneWeight += 0.75;
    if (hit.other) zoneWeight += 0.5;

    let evidence = 0;
    for (const line of lines) {
      if (!keywordMatchesResume(kw, line.toLowerCase())) continue;
      if (ACTION_VERBS.some(v => line.toLowerCase().includes(v))) evidence += 0.8;
      if (METRIC_PATTERN.test(line)) evidence += 0.8;
      if (evidence >= 1.6) break;
    }

    if (lower.includes(normalizeTerm(kw))) evidence += 0.2;
    scoreSum += Math.min(zoneWeight + evidence, 3.2);
  }

  return Math.round((scoreSum / (matched.length * 3.2)) * 100);
}

function computeRecencyScore(matched, resumeText) {
  if (!matched.length) return 0;
  const lines = resumeText.split('\n').map(l => l.trim()).filter(Boolean);
  const expStart = lines.findIndex(l => /\b(experience|досвід|work history|employment)\b/i.test(l));
  const experienceLines = expStart >= 0 ? lines.slice(expStart + 1) : lines;
  const recentWindow = experienceLines.slice(0, 24).join('\n').toLowerCase();
  const wholeExp = experienceLines.join('\n').toLowerCase();
  if (!wholeExp) return 0;

  let recentHits = 0;
  let anyHits = 0;
  for (const kw of matched) {
    if (keywordMatchesResume(kw, wholeExp)) anyHits += 1;
    if (keywordMatchesResume(kw, recentWindow)) recentHits += 1;
  }
  if (anyHits === 0) return 0;
  return Math.round((recentHits / anyHits) * 100);
}

function computeStuffingPenalty(resumeText) {
  const words = tokenize(resumeText).filter(t => !isNoiseKeyword(t));
  if (!words.length) return 0;
  const freq = {};
  for (const w of words) freq[w] = (freq[w] || 0) + 1;
  const maxFreq = Math.max(...Object.values(freq));
  const ratio = maxFreq / words.length;
  if (ratio < 0.03) return 0;
  if (ratio < 0.06) return 4;
  if (ratio < 0.09) return 9;
  return 14;
}

function normalizeTitleForMatch(title) {
  return String(title || '')
    .toLowerCase()
    .replace(/[^a-zа-яёіїєґ0-9\s-]/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function computeTitleAlignmentScore(jobText, resumeText) {
  const title = normalizeTitleForMatch(detectJobTitle(jobText));
  if (!title || title === 'спеціаліст') return 50;
  const resumeNorm = normalizeTitleForMatch(resumeText);
  if (!resumeNorm) return 0;
  if (resumeNorm.includes(title)) return 100;

  const tokens = title.split(' ').filter(t => t.length > 2);
  if (!tokens.length) return 40;
  let hit = 0;
  for (const t of tokens) {
    if (resumeNorm.includes(t)) hit += 1;
  }
  return Math.round((hit / tokens.length) * 100);
}

function extractKnockoutCandidates(jobText) {
  const lines = jobText.split('\n').map(l => l.trim()).filter(Boolean);
  const candidates = [];
  for (const line of lines) {
    if (/(must|required|mandatory|обов.?язков|вимоги|must-have|потрібно|необхідно)/i.test(line)) {
      candidates.push(line);
    }
  }
  return candidates.slice(0, 18);
}

function detectKnockoutRisks(jobText, resumeText) {
  const lowerJob = jobText.toLowerCase();
  const lowerResume = resumeText.toLowerCase();
  const risks = [];

  const yearsReq = lowerJob.match(/(\d+)\+?\s*(?:years?|роки?|років|рік)/i);
  if (yearsReq) {
    const requiredYears = parseInt(yearsReq[1], 10);
    const haveYears = detectYearsExp(resumeText);
    risks.push({
      label: `${requiredYears}+ років релевантного досвіду`,
      status: haveYears >= requiredYears ? 'covered' : 'likely_missing',
      detail: `Виявлено: ${haveYears} років`,
    });
  }

  if (/(on-?site|office|в офісі|на місці|тільки офіс)/i.test(lowerJob)) {
    const hasLocation = /(lviv|kyiv|к?иїв|львів|location|місто|city)/i.test(lowerResume);
    risks.push({
      label: 'Формат роботи on-site / office',
      status: hasLocation ? 'unclear' : 'likely_missing',
      detail: hasLocation ? 'Локація є, але готовність до on-site неявна' : 'Немає явного підтвердження готовності',
    });
  }

  if (/(work authorization|visa|sponsorship|дозвіл на роботу|право на працю)/i.test(lowerJob)) {
    const hasAuth = /(work authorization|дозвіл на роботу|громадянство|citizen|permanent resident)/i.test(lowerResume);
    risks.push({
      label: 'Право на працевлаштування / віза',
      status: hasAuth ? 'covered' : 'unclear',
      detail: hasAuth ? 'Є ознаки підтвердження' : 'Краще уточнити в резюме/супровідному листі',
    });
  }

  const mustLines = extractKnockoutCandidates(jobText);
  const mustTerms = uniqueNonEmpty(
    mustLines
      .flatMap(l => extractKeywords(l, 8).map(k => k.original))
      .filter(t => t.length >= 3 && !isNoiseKeyword(t))
  ).slice(0, 8);

  for (const t of mustTerms) {
    const covered = keywordMatchesResume(t, lowerResume);
    risks.push({
      label: `Must-have: ${t}`,
      status: covered ? 'covered' : 'likely_missing',
      detail: covered ? 'Знайдено в резюме' : 'Не знайдено прямого підтвердження',
    });
  }

  return uniqueNonEmpty(risks.map(r => JSON.stringify(r))).map(x => JSON.parse(x)).slice(0, 12);
}

function scoreATS(resumeText, jobText) {
  const cleanResumeText = sanitizeResumeSource(resumeText);
  const cleanJobText = sanitizeJobSource(jobText);

  const jdKeywords = extractKeywords(cleanJobText, 40);
  const resumeLower = cleanResumeText.toLowerCase();
  const zones = splitResumeZones(cleanResumeText);

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
  const sections = detectSections(cleanResumeText);
  const secTotal = sections.reduce((s, sec) => s + sec.weight, 0);
  const secFound = sections.reduce((sum, sec) => {
    if (!sec.found) return sum;
    const qualityFactor = sec.quality === 'good' ? 1 : 0.65;
    return sum + sec.weight * qualityFactor;
  }, 0);
  const secScore = Math.round((secFound / secTotal) * 100);

  // Format
  const formatIssues = checkFormat(cleanResumeText);
  const fmtPenalty = Math.min(formatIssues.reduce((s, i) => s + (i.severity === 'high' ? 20 : i.severity === 'medium' ? 10 : 5), 0), 30);
  const fmtScore = Math.max(100 - fmtPenalty, 30);

  // Contextual + recency + title + stuffing
  const contextScore = computeContextScore(matched, cleanResumeText, zones);
  const recencyScore = computeRecencyScore(matched, cleanResumeText);
  const titleScore = computeTitleAlignmentScore(cleanJobText, cleanResumeText);
  const stuffingPenalty = computeStuffingPenalty(cleanResumeText);
  const knockoutRisks = detectKnockoutRisks(cleanJobText, cleanResumeText);
  const formatFlags = formatIssues.map(i => ({
    key: i.key,
    status: i.severity === 'high' ? 'fail' : i.severity === 'medium' ? 'warn' : 'pass',
    title: i.msg,
    detail: i.severity === 'high' ? 'Критичний ризик для ATS-парсингу' : 'Бажано виправити для стабільного парсингу',
  }));

  // Weighted final score
  const baseScore =
    kwScore * 0.32 +
    contextScore * 0.22 +
    recencyScore * 0.14 +
    secScore * 0.12 +
    fmtScore * 0.10 +
    titleScore * 0.10;
  const knockoutPenalty = knockoutRisks.filter(r => r.status === 'likely_missing').length * 2;
  const score = Math.max(0, Math.min(100, Math.round(baseScore - stuffingPenalty - knockoutPenalty)));

  return {
    score,
    kwScore,
    secScore,
    fmtScore,
    contextScore,
    recencyScore,
    titleScore,
    stuffingPenalty,
    matched,
    missing,
    sections,
    formatIssues,
    knockoutRisks,
    formatFlags,
  };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --------------------------------------------------------
// RECOMMENDATION ENGINE
// --------------------------------------------------------
function buildRecommendations({
  score, kwScore, secScore, fmtScore, contextScore, recencyScore, titleScore,
  matched, missing, sections, formatIssues, knockoutRisks, stuffingPenalty,
}) {
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

  const weakSections = sections.filter(s => s.found && s.quality === 'weak');
  if (weakSections.length > 0) {
    recs.push({
      priority: 'medium',
      icon: '🧩',
      text: `<strong>Секції потребують наповнення:</strong> ${weakSections.map(s => s.label).join(', ')}.`,
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

  const knockoutMissing = (knockoutRisks || []).filter(r => r.status === 'likely_missing');
  const knockoutUnclear = (knockoutRisks || []).filter(r => r.status === 'unclear');
  if (knockoutMissing.length > 0) {
    recs.push({
      priority: 'high',
      icon: '🛑',
      text: `<strong>Knockout-ризики:</strong> ${knockoutMissing.slice(0, 3).map(r => r.label).join(', ')}.`,
    });
  } else if (knockoutUnclear.length > 0) {
    recs.push({
      priority: 'medium',
      icon: '🟠',
      text: `<strong>Є неявні вимоги:</strong> ${knockoutUnclear.slice(0, 3).map(r => r.label).join(', ')}. Варто уточнити в резюме.`,
    });
  }

  if (contextScore < 55) {
    recs.push({
      priority: 'high',
      icon: '🧠',
      text: '<strong>Слабкий контекстний доказ навичок.</strong> Додайте буліти у форматі: дія + інструмент + вимірюваний результат.',
    });
  }
  if (recencyScore < 50) {
    recs.push({
      priority: 'medium',
      icon: '🕒',
      text: '<strong>Низька актуальність досвіду.</strong> Підніміть релевантні технології у верхні (останні) позиції досвіду.',
    });
  }
  if (titleScore < 50) {
    recs.push({
      priority: 'medium',
      icon: '🎯',
      text: '<strong>Слабкий title alignment.</strong> Додайте цільову назву ролі у Summary/заголовок резюме.',
    });
  }
  if ((stuffingPenalty || 0) > 0) {
    recs.push({
      priority: 'medium',
      icon: '⚖️',
      text: '<strong>Ознаки keyword stuffing.</strong> Зменште повтори і залиште ключові слова тільки в релевантному контексті.',
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
    .replace(/\[!\[.*?\]\(.*?\)\]/g, ' ')
    .replace(/\[(.*?)\]\((https?:\/\/.*?)\)/g, '$1')
    .replace(/https?:\/\/\S+/g, ' ')
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

  const rawUrl = normalizeJobUrlInput(input.value);
  input.value = rawUrl;

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

  try {
    const { extracted, strategy } = await fetchJobContentWithStrategies(rawUrl);

    jobTextarea.value = extracted;
    document.getElementById('jobCount').textContent = `${countWords(extracted)} слів`;

    statusEl.className = 'fetch-status success';
    statusEl.textContent = `✅ Завантажено з ${parsedUrl.hostname} · ${countWords(extracted)} слів (${strategy})`;

    // Auto-switch to text view so user can review
    switchJobSource('text');

  } catch (err) {
    const rawReason = err && err.message ? String(err.message) : '';
    let msg = rawReason || 'Помилка мережі.';
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      msg = 'Час очікування вичерпано. Сайт або проксі тимчасово недоступні.';
    } else if (/CAPTCHA|Cloudflare|403|заблоковано|захист/i.test(msg)) {
      msg = `Сайт ${parsedUrl.hostname} блокує автоматичне завантаження (CAPTCHA/403). Вставте текст вакансії вручну.`;
    } else if (/Не вдалося отримати текст вакансії\./i.test(msg)) {
      msg = `${msg}\nПорада: спробуйте інше посилання або вставте текст вакансії вручну.`;
    } else if (/fetch|network|мережевий/i.test(msg)) {
      msg = 'Не вдалося підключитися до сайту/проксі. Перевірте інтернет або спробуйте ще раз за 1-2 хвилини.';
    }

    if (rawReason && !msg.includes(rawReason) && !/CAPTCHA|Cloudflare|403|захист/i.test(msg)) {
      msg += `\nДеталі: ${rawReason}`;
    }

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
  const {
    score, kwScore, secScore, fmtScore, contextScore, recencyScore, titleScore,
    matched, missing, sections, knockoutRisks, formatFlags,
  } = result;

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
    { label: 'Контекст', val: contextScore, color: 'linear-gradient(90deg,#10b981,#06b6d4)' },
    { label: 'Актуальність', val: recencyScore, color: 'linear-gradient(90deg,#0ea5e9,#22c55e)' },
    { label: 'Структура', val: secScore, color: 'linear-gradient(90deg,#8b5cf6,#6366f1)' },
    { label: 'Title Match', val: titleScore, color: 'linear-gradient(90deg,#f59e0b,#f97316)' },
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
    <div class="section-row ${s.found ? (s.quality === 'good' ? 'found' : 'weak') : 'missing'}">
      <span class="section-status">${s.found ? '✅' : '❌'}</span>
      <div class="section-meta">
        <span class="section-name">${s.label}</span>
        <span class="section-detail">${s.detail}</span>
      </div>
      <div class="section-actions">
        <span class="section-badge">${
          !s.found ? 'Відсутня' : s.quality === 'good' ? 'Добре' : 'Слабко'
        }</span>
        ${!s.found ? `<button class="section-fix-btn" onclick="appendSectionTemplate('${s.key}')">+ Додати</button>` : ''}
      </div>
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

  // Knockout risks
  const risks = (knockoutRisks || []);
  document.getElementById('knockoutList').innerHTML = risks.length
    ? risks.map((r) => `
      <div class="risk-item ${r.status}">
        <div class="risk-body">
          <div class="risk-title">${r.label}</div>
          <div class="risk-desc">${r.detail || ''}</div>
        </div>
      </div>
    `).join('')
    : '<div class="risk-item covered"><div class="risk-body"><div class="risk-title">Критичних knockout-ризиків не знайдено</div><div class="risk-desc">Перевірка пройдена.</div></div></div>';

  // ATS readiness checks
  const readiness = [
    ...(formatFlags || []),
    { key: 'noise', status: missing.length > 20 ? 'warn' : 'pass', title: 'Контроль шуму', detail: missing.length > 20 ? 'Багато нерелевантних термінів у порівнянні з JD' : 'Шум у допустимих межах' },
    { key: 'structure', status: secScore >= 80 ? 'pass' : secScore >= 60 ? 'warn' : 'fail', title: 'Структура ATS', detail: `Покриття секцій: ${secScore}%` },
    { key: 'coverage', status: kwScore >= 65 ? 'pass' : kwScore >= 45 ? 'warn' : 'fail', title: 'Покриття ключових вимог', detail: `Покриття: ${kwScore}%` },
  ];
  document.getElementById('readinessList').innerHTML = readiness.map((r) => `
    <div class="readiness-item ${r.status}">
      <div class="readiness-body">
        <div class="readiness-title">${r.title}</div>
        <div class="readiness-desc">${r.detail}</div>
      </div>
    </div>
  `).join('');
}

// --------------------------------------------------------
// EXPORT / COPY REPORT
// --------------------------------------------------------
function copyReport() {
  const resumeTextRaw = document.getElementById('resumeText').value;
  const jobTextRaw = document.getElementById('jobText').value;
  const resumeText = sanitizeResumeSource(resumeTextRaw);
  const jobText = sanitizeJobSource(jobTextRaw);

  if (!resumeText || !jobText) return;

  const result = scoreATS(resumeText, jobText);
  const {
    score, kwScore, secScore, fmtScore, contextScore, recencyScore, titleScore,
    matched, missing, sections, knockoutRisks,
  } = result;

  const report = `
╔══════════════════════════════════════╗
   ATS ANALYZER — ЗВІТ АНАЛІЗУ
╚══════════════════════════════════════╝

📊 ЗАГАЛЬНИЙ ATS SCORE: ${score}% — ${getScoreLabel(score)}

BREAKDOWN:
  🔑 Ключові слова:  ${kwScore}%
  🧠 Контекст:       ${contextScore}%
  🕒 Актуальність:   ${recencyScore}%
  🎯 Title Match:    ${titleScore}%
  📋 Структура:      ${secScore}%
  📄 Форматування:   ${fmtScore}%

ЗНАЙДЕНІ КЛЮЧОВІ СЛОВА (${matched.length}):
${matched.join(' · ')}

ВІДСУТНІ КЛЮЧОВІ СЛОВА (${missing.length}):
${missing.join(' · ')}

СЕКЦІЇ РЕЗЮМЕ:
${sections.map(s => `  ${s.found ? '✅' : '❌'} ${s.label}`).join('\n')}

KNOCKOUT RISKS:
${(knockoutRisks || []).map(r => `  ${r.status === 'covered' ? '✅' : r.status === 'unclear' ? '🟡' : '❌'} ${r.label} — ${r.detail || ''}`).join('\n') || '  ✅ Не виявлено'}

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
  const resumeRaw = document.getElementById('resumeText').value;
  const jobRaw = document.getElementById('jobText').value;
  const resumeText = sanitizeResumeSource(resumeRaw);
  const jobText = sanitizeJobSource(jobRaw);
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
  { key: 'certifications', labels: ['certification', 'certifications', 'certif', 'сертиф', 'сертифікати', 'ліцензії', 'licenses', 'courses', 'курси'] },
  { key: 'other', labels: ['languages', 'мови', 'projects', 'проєкти', 'awards', 'volunteer', 'досягнення', 'achievements', 'interests', 'інтереси', 'publications', 'публікації'] },
];

function isContactLine(line) {
  return /@/.test(line)
    || /\+?\d[\d\s().-]{7,}\d/.test(line)
    || /linkedin\.com|github\.com|behance\.net|t\.me\/|telegram|tg:|skype|portfolio|website/i.test(line)
    || /\b(phone|tel|e-?mail|email|contact|contacts|контакт|телефон|пошта|адрес|address|location|локац|місто|city|date of birth|дата народження|nationality|громадянство)\b/i.test(line);
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
  const result = { name: '', contact: '', header: '', summary: '', experience: '', education: '', skills: '', certifications: '', other: '', raw: text };
  const lines = text
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .filter(l => !isResumeNoiseLine(l));
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

  // Collect contact lines (limit to header area to avoid pulling URLs from body sections)
  const contactSource = topLines.length ? topLines : lines.slice(0, Math.min(lines.length, 12));
  const contactLines = contactSource.filter(l => isContactLine(l));
  const contactLineSet = new Set(contactLines);
  result.contact = uniqueNonEmpty(contactLines).join('\n');

  // Preserve original header lines from the top block (title, location, links, etc.)
  const headerLines = topLines.filter(l => !isSectionHeading(l) && !isResumeNoiseLine(l));
  result.header = uniqueNonEmpty(headerLines).join('\n');

  // Parse sections
  let cur = null;
  const buckets = { summary: [], experience: [], education: [], skills: [], certifications: [], other: [] };

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
  result.certifications = buckets.certifications.join('\n');
  result.other = buckets.other.join('\n');
  return result;
}

function sanitizeJobTitleCandidate(rawTitle) {
  return String(rawTitle || '')
    .replace(/\[!\[.*?\]\(.*?\)\]/g, ' ')
    .replace(/\[(.*?)\]\(.*?\)/g, '$1')
    .replace(/[#*_`>]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isLikelyJobTitle(text) {
  const t = String(text || '').trim();
  if (t.length < 3 || t.length > 80) return false;
  if (/https?:\/\/|www\.|@|cdn-cgi|social-icons|image\s*\d+/i.test(t)) return false;
  if (/до пошуку|відгукнутись|готові розглядати|повна зайнятість|безкоштовне навчання|медичне страхування/i.test(t)) return false;
  if ((t.match(/[|]/g) || []).length >= 2) return false;
  const words = t.split(/\s+/);
  if (words.length > 10) return false;
  return true;
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
      const title = sanitizeJobTitleCandidate(m[1]).replace(/[.\s]+$/, '');
      if (isLikelyJobTitle(title)) return title;
    }
  }
  // Fallback: first line that looks like a job title
  const lines = jobText.split('\n').map(l => l.trim()).filter(l => l.length > 3);
  for (const line of lines) {
    const title = sanitizeJobTitleCandidate(line).replace(/[.\s]+$/, '');
    if (!isLikelyJobTitle(title)) continue;
    if (/developer|engineer|manager|designer|analyst|architect|lead|specialist|consultant|devops|маркетолог|розробник|інженер|менеджер|дизайнер|аналітик|адміністратор/i.test(title)) {
      return title;
    }
  }
  return 'Спеціаліст';
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
function rewriteResume(parsed, matched, _missing, jobText) {
  const jobTitle = detectJobTitle(jobText);
  const years = detectYearsExp(parsed.raw);
  const topMatched = uniqueNonEmpty(matched).filter(k => !isNoiseKeyword(k)).slice(0, 8);
  const buildSummary = () => {
    const baseSummary = sanitizeSectionText(parsed.summary, 10)
      .split('\n')
      .filter((line) => !/акцентувати|додати за наявності|релевантно до вакансії/i.test(line))
      .join('\n')
      .trim();
    if (baseSummary) {
      if (jobTitle && jobTitle !== 'Спеціаліст' && !baseSummary.toLowerCase().includes(jobTitle.toLowerCase())) {
        return `${baseSummary}\nЦільова позиція: ${jobTitle}.`;
      }
      return baseSummary;
    }
    const skillsLead = topMatched.slice(0, 4).join(', ');
    let generated = `Фахівець із ${years}+ роками професійного досвіду.`;
    if (skillsLead) generated += ` Ключові компетенції: ${skillsLead}.`;
    if (jobTitle && jobTitle !== 'Спеціаліст') generated += ` Цільова позиція: ${jobTitle}.`;
    return generated.trim();
  };

  const normalizeLine = (line) => String(line || '')
    .replace(/^[•\-\*→▹▸▪●]+\s*/, '')
    .replace(/^\d+[.)]\s*/, '')
    .replace(/\s{2,}/g, ' ')
    .trim();

  const splitSkillItems = (text) => String(text || '')
    .replace(/\n/g, ',')
    .split(/[;,|]/)
    .map((item) => normalizeLine(item))
    .filter(Boolean)
    .filter((item) => item.length >= 2 && item.length <= 50)
    .filter((item) => !isNoiseKeyword(item))
    .filter((item) => item.split(/\s+/).length <= 6);

  const buildCoreSkills = () => {
    const resumeLower = String(parsed.raw || '').toLowerCase();
    const originalSkills = splitSkillItems(sanitizeSectionText(parsed.skills, 40));
    const matchedSkills = topMatched.filter((term) => keywordMatchesResume(term, resumeLower));
    const merged = uniqueNonEmpty([...originalSkills, ...matchedSkills]).slice(0, 16);
    if (!merged.length) return '';
    return merged.map((item) => `• ${item}`).join('\n');
  };

  const looksLikeExperienceHeading = (line) => {
    const t = String(line || '').trim();
    if (!t) return false;
    if (/\b(?:з\s*\d{1,2}[./]\d{4}\s*по\s*(?:\d{1,2}[./]\d{4}|нині|досі|тепер)|(?:19|20)\d{2}\s*[-–]\s*(?:present|current|нині|досі|(?:19|20)\d{2}))\b/i.test(t)) return true;
    if (/\(\d+\s*(?:рок|місяц)/i.test(t)) return true;
    if (/^[A-ZА-ЯІЇЄҐ][^.!?]{2,100}$/.test(t) && /(ТОВ|ПП|ФОП|LLC|Inc|Ltd|департамент|школа|університет|company)/i.test(t)) return true;
    return false;
  };

  const normalizeExperience = (text) => {
    const clean = sanitizeSectionText(text, 140);
    const lines = clean.split('\n').map((line) => normalizeLine(line)).filter(Boolean);
    const out = [];
    for (const line of lines) {
      if (isResumeNoiseLine(line)) continue;
      if (looksLikeExperienceHeading(line)) {
        if (out.length && out[out.length - 1] !== '') out.push('');
        out.push(line);
        continue;
      }
      out.push(`• ${line}`);
    }
    while (out.length && out[0] === '') out.shift();
    while (out.length && out[out.length - 1] === '') out.pop();
    return out.join('\n');
  };

  const normalizeEducation = (text) => {
    const clean = sanitizeSectionText(text, 80);
    const lines = clean.split('\n').map((line) => normalizeLine(line)).filter(Boolean);
    const out = [];
    for (const line of lines) {
      if (isResumeNoiseLine(line)) continue;
      if (/(університет|university|інститут|institute|коледж|college|бакалавр|магістр|bachelor|master|degree|освіта|education)/i.test(line)) {
        out.push(line);
      } else {
        out.push(`• ${line}`);
      }
    }
    return out.join('\n');
  };

  const normalizeCertifications = (text) => {
    const clean = sanitizeSectionText(text, 60);
    const lines = clean.split('\n').map((line) => normalizeLine(line)).filter(Boolean);
    const out = [];
    for (const line of lines) {
      if (isResumeNoiseLine(line)) continue;
      out.push(line.startsWith('• ') ? line : `• ${line}`);
    }
    return out.join('\n');
  };

  const summary = buildSummary();
  const coreSkills = buildCoreSkills();
  const experienceSource = parsed.experience && parsed.experience.trim().length > 10
    ? parsed.experience
    : inferExperienceFromRaw(parsed.raw);
  const educationSource = parsed.education && parsed.education.trim().length > 10
    ? parsed.education
    : inferEducationFromRaw(parsed.raw);
  const certificationsSource = parsed.certifications && parsed.certifications.trim().length > 6
    ? parsed.certifications
    : inferCertificationsFromRaw(parsed.raw);

  const finalExperience = normalizeExperience(experienceSource);
  const finalEducation = normalizeEducation(educationSource);
  const finalCertifications = normalizeCertifications(certificationsSource);

  const headerLines = uniqueNonEmpty(
    (parsed.header || '')
      .split('\n')
      .map(x => x.trim())
      .filter(x => !isResumeNoiseLine(x))
  );
  const contactParts = uniqueNonEmpty(
    (parsed.contact || '')
      .split(/\n|\|/)
      .map(x => x.trim())
      .filter(x => !isResumeNoiseLine(x))
  );

  let finalName = (parsed.name || '').trim();
  if (!finalName) {
    finalName = headerLines.find(l => !isContactLine(l)) || headerLines[0] || '';
  }

  const headerWithoutName = headerLines.filter(l => l !== finalName);
  const finalContact = uniqueNonEmpty([...headerWithoutName, ...contactParts]).join('\n');

  return {
    name: finalName,
    contact: finalContact,
    summary,
    coreSkills,
    skills: coreSkills, // compatibility with existing flows
    experience: finalExperience,
    education: finalEducation,
    certifications: finalCertifications,
    other: sanitizeSectionText(parsed.other, 20),
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

function inferCertificationsFromRaw(rawText) {
  const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
  const certLines = [];

  for (const line of lines) {
    if (/(сертиф|certif|course|курси|academy|prometheus|cisco|google|azure|aws|comptia|palo alto|udemy|coursera)/i.test(line)) {
      certLines.push(line);
    }
    if (certLines.length >= 16) break;
  }

  if (certLines.length > 0) return certLines.join('\n');
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
    { icon: '🔧', title: 'Core Skills', body: adapted.coreSkills || adapted.skills },
    { icon: '💼', title: 'Досвід роботи', body: adapted.experience },
    { icon: '🎓', title: 'Освіта', body: adapted.education },
    { icon: '📜', title: 'Сертифікації', body: adapted.certifications },
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
    const resumeText = sanitizeResumeSource(document.getElementById('resumeText').value);
    const jobText = sanitizeJobSource(document.getElementById('jobText').value);
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
  if (adapted.contact) {
    const contactLines = adapted.contact.split('\n').map(s => s.trim()).filter(Boolean);
    contactLines.forEach((line, idx) => {
      children.push(new Paragraph({
        children: [new TextRun({ text: line, color: '555577', size: 18, font: 'Calibri' })],
        alignment: AlignmentType.CENTER,
        spacing: { after: idx === contactLines.length - 1 ? 120 : 30 },
      }));
    });
  }

  const sections = [
    { title: 'Профіль / Summary', text: adapted.summary },
    { title: 'Core Skills', text: adapted.coreSkills || adapted.skills },
    { title: 'Досвід роботи', text: adapted.experience },
    { title: 'Освіта', text: adapted.education },
    { title: 'Сертифікації', text: adapted.certifications },
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
  if (adapted.contact) {
    for (const line of adapted.contact.split('\n').map(s => s.trim()).filter(Boolean)) {
      addLine(line, { size: 9, align: 'center', color: [110, 110, 140], spacing: 2.5 });
    }
    y += 3.5;
  }

  doc.setDrawColor(200, 200, 220);
  doc.setLineWidth(0.2);
  doc.line(ML, y, PW - MR, y);
  y += 6;

  const secs = [
    { title: 'Профіль / Summary', text: adapted.summary },
    { title: 'Core Skills', text: adapted.coreSkills || adapted.skills },
    { title: 'Досвід роботи', text: adapted.experience },
    { title: 'Освіта', text: adapted.education },
    { title: 'Сертифікації', text: adapted.certifications },
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
