// Report text comes from an untrusted jar, so it is only ever inserted via textContent.

const MAX_FILE_BYTES = 100 * 1024 * 1024;

const VERDICTS = {
  clean: { label: 'Опасного не найдено', tone: 'ok' },
  suspicious: { label: 'Подозрительно', tone: 'warn' },
  malicious: { label: 'Вредоносный', tone: 'bad' },
  unknown: { label: 'Не удалось оценить', tone: 'muted' },
};

const SEVERITY = { low: 'низкая', medium: 'средняя', high: 'высокая', critical: 'критическая' };
const CONFIDENCE = { low: 'низкая', medium: 'средняя', high: 'высокая' };
const OBFUSCATION = { none: 'нет', low: 'слабая', medium: 'средняя', high: 'сильная' };

const $ = (id) => document.getElementById(id);
const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
let lastReport = null;
let lastFileName = '';

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(text, isError = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', isError);
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  return `${(bytes / 1024 / 1024).toFixed(1)} МБ`;
}

function runScan(buffer) {
  return new Promise((resolve, reject) => {
    worker.onmessage = ({ data }) => (data.ok ? resolve(data) : reject(new Error(data.error)));
    worker.onerror = (event) => reject(new Error(event.message || 'worker failed'));
    worker.postMessage(buffer, [buffer]);
  });
}

async function handleFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    setStatus(`Файл больше ${formatBytes(MAX_FILE_BYTES)} — такие не сканируются.`, true);
    return;
  }
  $('result').hidden = true;
  $('drop').classList.add('busy');
  setStatus(`Сканирую ${file.name}…`);
  try {
    const buffer = await file.arrayBuffer();
    const hash = await sha256Hex(buffer);
    const { result, elapsedMs } = await runScan(buffer);
    lastReport = { file: file.name, sha256: hash, ...result };
    lastFileName = file.name;
    render(file, hash, result, elapsedMs);
    setStatus('');
  } catch (error) {
    setStatus(`Ошибка скана: ${error.message}`, true);
  } finally {
    $('drop').classList.remove('busy');
  }
}

function evidenceLine(evidence) {
  const where = evidence.class_name
    ? [evidence.class_name, evidence.method_name].filter(Boolean).join('.')
    : evidence.resource_path || evidence.archive_path;
  const value = evidence.value_preview || evidence.target_value || evidence.source_value;
  const parts = [evidence.operation, where, value && `«${value}»`].filter(Boolean);
  return parts.join(' · ');
}

function evidenceList(evidence) {
  if (!evidence?.length) return null;
  const details = el('details', 'evidence');
  details.append(el('summary', null, `Доказательства (${evidence.length})`));
  const list = el('ul');
  for (const item of evidence.slice(0, 20)) list.append(el('li', null, evidenceLine(item)));
  details.append(list);
  return details;
}

// Empty lists are omitted from the serialized report, so they arrive as undefined.
function section(title, items = [], renderItem) {
  if (!items.length) return null;
  const wrap = el('section', 'block');
  wrap.append(el('h2', null, `${title} · ${items.length}`));
  const list = el('ul', 'items');
  for (const item of items) list.append(renderItem(item));
  wrap.append(list);
  return wrap;
}

function itemCard(title, meta, message, evidence, tone) {
  const li = el('li', `item ${tone ?? ''}`);
  const head = el('div', 'item-head');
  head.append(el('code', null, title));
  if (meta) head.append(el('span', 'meta', meta));
  li.append(head);
  if (message) li.append(el('p', null, message));
  const ev = evidenceList(evidence);
  if (ev) li.append(ev);
  return li;
}

function severityTone(severity) {
  return severity === 'critical' || severity === 'high' ? 'bad' : severity === 'medium' ? 'warn' : '';
}

function render(file, hash, { summary, report }, elapsedMs) {
  const verdict = VERDICTS[report.verdict] ?? VERDICTS.unknown;
  $('verdict').dataset.tone = verdict.tone;
  $('verdict-label').textContent = verdict.label;
  $('verdict-file').textContent = `${file.name} · ${formatBytes(file.size)}`;
  $('score').textContent = report.risk_score;
  $('summary').textContent = summary;

  const coverage = report.analysis_coverage;
  const facts = [
    ['SHA-256', hash],
    ['Уверенность', CONFIDENCE[report.confidence] ?? report.confidence],
    ['Обфускация', `${OBFUSCATION[report.obfuscation.level] ?? report.obfuscation.level} (${report.obfuscation.score}/100)`],
    ['Покрытие анализа', `${coverage.score}% · классов ${coverage.parsed_classes}/${coverage.total_classes}`],
    ['Время скана', `${Math.round(elapsedMs)} мс`],
  ];
  $('facts').replaceChildren(...facts.flatMap(([k, v]) => [el('dt', null, k), el('dd', null, v)]));

  const sections = [
    section('Подтверждённые цепочки', report.confirmed_chains, (c) =>
      itemCard(c.rule_id, `${SEVERITY[c.severity] ?? c.severity} · +${c.score_contribution}`, (c.operations ?? []).join(' → '), c.evidence, severityTone(c.severity))),
    section('Находки', report.findings, (f) =>
      itemCard(f.rule_id, `${SEVERITY[f.severity] ?? f.severity} · +${f.score_contribution}`, f.message, f.evidence, severityTone(f.severity))),
    section('Возможности (сами по себе не опасны)', report.capabilities, (c) =>
      itemCard(c.rule_id, null, c.message, c.evidence)),
    section('Расшифрованные строки', report.decoded_strings, (d) =>
      itemCard(d.decoder_method, CONFIDENCE[d.confidence], d.decoded_value, [d.evidence])),
    section('Ограничения анализа', report.limitations, (l) =>
      itemCard(l.code, null, l.message, l.evidence, 'muted')),
  ].filter(Boolean);
  if (!sections.length) sections.push(el('p', 'empty', 'Ни находок, ни особых возможностей не обнаружено.'));
  $('sections').replaceChildren(...sections);

  $('result').hidden = false;
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

$('file').addEventListener('change', (event) => handleFile(event.target.files[0]));

const drop = $('drop');
for (const type of ['dragenter', 'dragover']) {
  drop.addEventListener(type, (event) => {
    event.preventDefault();
    drop.classList.add('over');
  });
}
for (const type of ['dragleave', 'drop']) {
  drop.addEventListener(type, () => drop.classList.remove('over'));
}
drop.addEventListener('drop', (event) => {
  event.preventDefault();
  handleFile(event.dataTransfer.files[0]);
});

$('download').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const link = el('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${lastFileName.replace(/\.[^.]+$/, '')}.ratscan.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

$('reset').addEventListener('click', () => {
  $('result').hidden = true;
  $('file').value = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
