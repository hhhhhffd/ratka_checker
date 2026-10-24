// Report text comes from an untrusted jar, so it is only ever inserted via textContent.
// Scanner messages are written in Russian; the page labels items by rule id instead
// and keeps the original messages in the downloadable JSON.

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const HEX_BYTES = 64;
const HEX_ROW = 8;

// First 64 bytes of a real mod jar: the ZIP signature, then the first entry name.
const SAMPLE_HEADER = [
  0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x08, 0x00, 0x00, 0x0a, 0x56, 0xf5, 0x5c, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x04, 0x00, 0x4d, 0x45,
  0x54, 0x41, 0x2d, 0x49, 0x4e, 0x46, 0x2f, 0xfe, 0xca, 0x00, 0x00, 0x50, 0x4b, 0x03, 0x04, 0x14,
  0x00, 0x08, 0x08, 0x08, 0x00, 0x0a, 0x56, 0xf5, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const VERDICTS = {
  clean: 'No dangerous chain found',
  suspicious: 'Suspicious',
  malicious: 'Malicious',
  unknown: 'No reliable verdict',
};
const OBFUSCATION = { none: 'None', low: 'Light', medium: 'Moderate', high: 'Heavy' };
const ACRONYMS = new Set(['http', 'https', 'url', 'jvm', 'zip', 'jar', 'cfg', 'rat', 'api', 'jni', 'dns', 'ip', 'sha256', 'vt', 'av', 'os', 'rpc', 'json']);
// Abort reasons produced before any class could be analyzed.
const ARCHIVE_FAILURE_CATEGORIES = new Set(['archive_structure', 'static_scan']);

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

function humanize(id) {
  const words = String(id).toLowerCase().split(/[_\s]+/).filter(Boolean)
    .map((word) => (ACRONYMS.has(word) ? word.toUpperCase() : word));
  const text = words.join(' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function listPhrase(items) {
  const unique = [...new Set(items)];
  if (unique.length <= 1) return unique.join('');
  return `${unique.slice(0, -1).join(', ')} and ${unique.at(-1)}`;
}

function classCount(count) {
  return `${count} ${count === 1 ? 'class' : 'classes'}`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function setStatus(text, isError = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', isError);
}

function renderHex(bytes, name, note) {
  $('hex-name').textContent = name;
  $('hex-note').textContent = note;
  const body = $('hex-body');
  body.replaceChildren();
  for (let start = 0; start < bytes.length; start += HEX_ROW) {
    const row = el('span', 'row');
    row.style.animationDelay = `${(start / HEX_ROW) * 35}ms`;
    row.append(el('span', 'off', `${start.toString(16).padStart(4, '0')}  `));
    const slice = bytes.slice(start, start + HEX_ROW);
    slice.forEach((byte, index) => {
      const isSignature = isZipSignatureAt(bytes, start + index);
      row.append(el('span', isSignature ? 'mark' : null, byte.toString(16).padStart(2, '0')));
      row.append(document.createTextNode(' '));
    });
    const ascii = Array.from(slice, (byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.')).join('');
    row.append(el('span', 'ascii', ` ${ascii}`));
    body.append(row);
  }
}

// True when the byte belongs to a "PK\x03\x04" local file header signature.
function isZipSignatureAt(bytes, offset) {
  for (let start = Math.max(0, offset - 3); start <= offset; start += 1) {
    if (bytes[start] === 0x50 && bytes[start + 1] === 0x4b && bytes[start + 2] === 0x03 && bytes[start + 3] === 0x04) {
      return true;
    }
  }
  return false;
}

function runScan(buffer) {
  return new Promise((resolve, reject) => {
    worker.onmessage = ({ data }) => (data.ok ? resolve(data) : reject(new Error(data.error)));
    worker.onerror = (event) => reject(new Error(event.message || 'The scanner worker stopped.'));
    worker.postMessage(buffer, [buffer]);
  });
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function handleFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    setStatus(`${file.name} is ${formatBytes(file.size)}. Files over ${formatBytes(MAX_FILE_BYTES)} are not scanned.`, true);
    return;
  }
  $('result').hidden = true;
  $('drop').classList.add('busy');
  setStatus(`Scanning ${file.name}…`);
  try {
    const buffer = await file.arrayBuffer();
    renderHex(new Uint8Array(buffer.slice(0, HEX_BYTES)), file.name, `${formatBytes(file.size)} · first ${Math.min(HEX_BYTES, file.size)} bytes`);
    const hash = await sha256Hex(buffer);
    const { result, elapsedMs } = await runScan(buffer);
    lastReport = { file: file.name, sha256: hash, ...result };
    lastFileName = file.name;
    render(hash, result.report, elapsedMs);
    setStatus('');
  } catch (error) {
    setStatus(`The scan failed: ${error.message}`, true);
  } finally {
    $('drop').classList.remove('busy');
    $('file').value = '';
  }
}

function summarize(report) {
  const findings = report.findings ?? [];
  const chains = report.confirmed_chains ?? [];
  const riskCategories = findings.filter((f) => f.score_contribution > 0).map((f) => humanize(f.category).toLowerCase());
  switch (report.verdict) {
    case 'malicious':
      return chains.length
        ? `Confirmed chain: ${listPhrase(chains.map((c) => humanize(c.rule_id).replace(/^Confirmed /, '').toLowerCase()))}.`
        : `Strong evidence of ${listPhrase(riskCategories) || 'dangerous behavior'}.`;
    case 'suspicious':
      return `Risky behavior found${riskCategories.length ? `: ${listPhrase(riskCategories)}` : ''}. Review before installing.`;
    case 'clean':
      return `Checked ${classCount(report.analysis_coverage.parsed_classes)}. Static analysis cannot prove a mod is safe, only that nothing dangerous connected.`;
    default: {
      const abort = findings.find((f) => ARCHIVE_FAILURE_CATEGORIES.has(f.category));
      if (abort) return `The archive could not be analyzed: ${humanize(abort.rule_id).toLowerCase()}.`;
      const gaps = (report.limitations ?? []).map((l) => humanize(l.code).toLowerCase());
      return `Too much of the code could not be analyzed to call it clean${gaps.length ? ` (${listPhrase(gaps.slice(0, 3))})` : ''}.`;
    }
  }
}

function evidenceLine(evidence) {
  const where = evidence.class_name
    ? [evidence.class_name, evidence.method_name].filter(Boolean).join('.')
    : evidence.resource_path || evidence.archive_path;
  const value = evidence.value_preview || evidence.target_value || evidence.source_value;
  return [evidence.operation, where, value && `"${value}"`].filter(Boolean).join('  ·  ');
}

function evidenceBlock(evidence) {
  const items = (evidence ?? []).filter(Boolean);
  if (!items.length) return null;
  const details = el('details', 'evidence');
  details.append(el('summary', null, `Evidence (${items.length})`));
  const list = el('ul');
  for (const item of items.slice(0, 20)) list.append(el('li', null, evidenceLine(item)));
  details.append(list);
  return details;
}

function item({ severity, title, meta, detail, evidence }) {
  const li = el('li', 'item');
  li.append(el('span', `sev ${severity ?? ''}`, severity ?? 'info'));
  const body = el('div');
  body.append(el('p', 'item-title', title));
  if (meta) body.append(el('p', 'item-meta', meta));
  if (detail) body.append(el('p', 'item-detail', detail));
  const ev = evidenceBlock(evidence);
  if (ev) body.append(ev);
  li.append(body);
  return li;
}

// Empty lists are omitted from the serialized report, so they arrive as undefined.
function group(title, note, entries = [], toItem) {
  if (!entries.length) return null;
  const section = el('section', 'group');
  const head = el('div', 'group-head');
  head.append(el('h3', null, title), el('span', 'count', String(entries.length)));
  section.append(head);
  if (note) section.append(el('p', 'group-note', note));
  const list = el('ul', 'items');
  for (const entry of entries) list.append(item(toItem(entry)));
  section.append(list);
  return section;
}

function render(hash, report, elapsedMs) {
  const verdict = $('verdict');
  verdict.dataset.tone = report.verdict;
  $('verdict-label').textContent = VERDICTS[report.verdict] ?? VERDICTS.unknown;
  $('summary').textContent = summarize(report);
  $('score').textContent = report.risk_score;
  $('meter-fill').style.width = '0';
  requestAnimationFrame(() => requestAnimationFrame(() => {
    $('meter-fill').style.width = `${report.risk_score}%`;
  }));

  const coverage = report.analysis_coverage;
  const facts = [
    ['Classes parsed', `${coverage.parsed_classes} / ${coverage.total_classes}`],
    ['Coverage', `${coverage.score}%`],
    ['Obfuscation', OBFUSCATION[report.obfuscation.level] ?? humanize(report.obfuscation.level)],
    ['Scan time', `${Math.max(1, Math.round(elapsedMs))} ms`],
  ];
  $('facts').replaceChildren(...facts.map(([term, value]) => {
    const cell = el('div');
    cell.append(el('dt', null, term), el('dd', null, value));
    return cell;
  }));

  const sections = [
    group('Confirmed chains', 'Data traced from a source to a dangerous sink.', report.confirmed_chains, (c) => ({
      severity: c.severity, title: humanize(c.rule_id), meta: `+${c.score_contribution} risk`,
      detail: (c.operations ?? []).join('  →  '), evidence: c.evidence,
    })),
    group('Findings', null, report.findings, (f) => ({
      severity: f.severity, title: humanize(f.rule_id),
      meta: [
        humanize(f.category),
        f.scope && f.scope !== 'unknown' ? humanize(f.scope) : null,
        f.score_contribution ? `+${f.score_contribution} risk` : null,
      ].filter(Boolean).join(' · '),
      evidence: f.evidence,
    })),
    group('Capabilities', 'What the code can do. Not risky on its own.', report.capabilities, (c) => ({
      title: humanize(c.rule_id), evidence: c.evidence,
    })),
    group('Decoded strings', 'Hidden values the scanner recovered.', report.decoded_strings, (d) => ({
      title: d.decoded_value, meta: humanize(d.decoder_method), evidence: [d.evidence],
    })),
    group('Analysis gaps', 'Parts of the code the scanner could not fully follow.', report.limitations, (l) => ({
      title: humanize(l.code), evidence: l.evidence,
    })),
  ].filter(Boolean);
  if (!sections.length) sections.push(el('p', 'empty', 'Nothing to report: no findings, capabilities or analysis gaps.'));
  const hashLine = el('p', 'hash', `SHA-256 ${hash}`);
  $('sections').replaceChildren(hashLine, ...sections);

  $('result').hidden = false;
  $('result').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

renderHex(SAMPLE_HEADER, 'example.jar', 'first 64 bytes');

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
  renderHex(SAMPLE_HEADER, 'example.jar', 'first 64 bytes');
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
