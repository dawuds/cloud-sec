/* Cloud Security Framework — SPA v2.0
   GRC Presentation Standard compliant.
   8-tab navigation, hash-routed, auditor-flow control detail.
*/

'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
const cache = new Map();

// ─── Fetch error UI ──────────────────────────────────────────────────────────
function renderFetchError(el, url, error) {
  el.innerHTML = '<div class="fetch-error">' +
    '<h2>Failed to load data</h2>' +
    '<p>Could not fetch <strong>' + escHtml(url) + '</strong></p>' +
    (error ? '<p class="error-detail">' + escHtml(String(error)) + '</p>' : '') +
    '<button onclick="location.reload()">Retry</button>' +
    '</div>';
}

// ─── Data loader ─────────────────────────────────────────────────────────────
async function load(path) {
  if (cache.has(path)) return cache.get(path);
  try {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    cache.set(path, data);
    return data;
  } catch (e) {
    console.error(`Failed to load ${path}:`, e);
    const app = document.getElementById('app');
    if (app) renderFetchError(app, path, e);
    return null;
  }
}

// ─── Router ──────────────────────────────────────────────────────────────────
function navigate(hash) {
  location.hash = '#' + hash;
}

function parseHash() {
  const raw = location.hash.slice(1) || 'overview';
  const parts = raw.split('/');
  return { view: parts[0], sub: parts[1] || null, extra: parts[2] || null };
}

async function route() {
  const { view, sub, extra } = parseHash();
  updateNav(view);
  const app = document.getElementById('app');
  app.innerHTML = '<div class="loading"><div class="spinner"></div><span>Loading...</span></div>';
  try {
    await render(view, sub, extra);
  } catch (e) {
    app.innerHTML = `<div class="error-state"><h2>Failed to load data</h2><p class="error-message">${escHtml(e.message)}</p><button onclick="location.reload()">Retry</button></div>`;
    console.error(e);
  }
}

function updateNav(view) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.view === view);
  });
}

// ─── Main dispatcher ─────────────────────────────────────────────────────────
async function render(view, sub, extra) {
  switch (view) {
    case 'overview':      return renderOverview();
    case 'framework':     return renderFramework(sub, extra);
    case 'controls':      return renderControls();
    case 'control':       return renderControlDetail(sub);
    case 'risk':          return renderRisk(sub);
    case 'threats':       return renderThreats(sub);
    case 'threat':        return renderThreatDetail(sub);
    case 'sectors':       return renderSectors();
    case 'sector':        return renderSectorDetail(sub);
    case 'architecture':  return renderArchitecture(sub);
    case 'reference':     return renderReference(sub);
    case 'search':        return renderSearch(sub);
    default:              return renderOverview();
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function setApp(html) { document.getElementById('app').innerHTML = html; }

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function tagList(arr) {
  if (!arr || !arr.length) return '';
  return `<div class="tag-list">${arr.map(t => `<span class="tag">${escHtml(t)}</span>`).join('')}</div>`;
}

function typeBadge(type) {
  if (!type) return '';
  const cls = { preventive:'type-preventive', detective:'type-detective', corrective:'type-corrective' }[type] || '';
  return `<span class="badge badge-${cls}">${escHtml(type)}</span>`;
}

function priorityBadge(p) {
  if (!p) return '';
  const cls = { critical:'mandatory', high:'mandatory', medium:'artifacts', low:'category' }[p] || 'category';
  return `<span class="badge badge-${cls}">${escHtml(p)}</span>`;
}

function cspBadge(csp) {
  if (!csp) return '';
  const id = String(csp).toLowerCase().replace(/\s+/g,'-');
  return `<span class="badge badge-csp-${id}">${escHtml(csp)}</span>`;
}

function ccmBadge(codes) {
  if (!codes || !codes.length) return '';
  return (Array.isArray(codes) ? codes : [codes]).map(c => `<span class="badge badge-domain" style="--domain-color:var(--type-preventive)">${escHtml(c)}</span>`).join(' ');
}

function nacsaBadge(codes) {
  if (!codes || !codes.length) return '';
  return codes.map(c => `<span class="badge badge-evidence">${escHtml(c)}</span>`).join(' ');
}

function safeJoin(val, sep) {
  if (Array.isArray(val)) return val.join(sep || ', ');
  return String(val || '');
}

function buildSubTabs(tabs, activeIdx) {
  return `<div class="sub-tabs">${tabs.map((t, i) =>
    `<button class="sub-tab${i === activeIdx ? ' active' : ''}" data-sub="${escHtml(t.key)}">${escHtml(t.label)}</button>`
  ).join('')}</div>`;
}

function buildSubPanels(tabs, contents, activeIdx) {
  return tabs.map((t, i) =>
    `<div class="sub-panel${i === activeIdx ? ' active' : ''}" data-subpanel="${escHtml(t.key)}">${contents[i]}</div>`
  ).join('');
}

function initSubTabs() {
  document.querySelectorAll('.sub-tabs').forEach(bar => {
    bar.addEventListener('click', (e) => {
      const btn = e.target.closest('.sub-tab');
      if (!btn) return;
      const key = btn.dataset.sub;
      bar.querySelectorAll('.sub-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const container = bar.parentElement;
      container.querySelectorAll('.sub-panel').forEach(p => {
        p.classList.toggle('active', p.dataset.subpanel === key);
      });
    });
  });
}

function initAccordions() {
  document.querySelectorAll('.accordion-trigger').forEach(trigger => {
    trigger.addEventListener('click', () => {
      const content = trigger.nextElementSibling;
      const expanded = trigger.getAttribute('aria-expanded') === 'true';
      trigger.setAttribute('aria-expanded', !expanded);
      content.hidden = expanded;
    });
  });
}

// ─── OVERVIEW ────────────────────────────────────────────────────────────────
async function renderOverview() {
  const [reqs, controls, incidents, actors, sectors, domains] = await Promise.all([
    load('requirements/index.json'),
    load('controls/library.json'),
    load('threats/known-incidents.json'),
    load('threats/threat-actors.json'),
    load('sectors/index.json'),
    load('standards/csa-ccm/control-domains.json'),
  ]);

  const domainCount = reqs.domains ? reqs.domains.length : 12;
  const controlCount = Array.isArray(controls) ? controls.length : (controls.controls ? controls.controls.length : 0);
  const incidentCount = incidents.incidents ? incidents.incidents.length : 0;
  const actorCount = actors.threatActors ? actors.threatActors.length : 0;
  const sectorCount = sectors.sectors ? sectors.sectors.length : 0;
  const ccmDomainCount = Array.isArray(domains) ? domains.length : (domains.controlDomains ? domains.controlDomains.length : 17);

  const quickLinks = [
    { label: 'CSA CCM v4 Control Domains', hash: 'framework/ccm-domains', desc: `${ccmDomainCount} domains — the primary cloud security framework` },
    { label: 'Shared Responsibility Model', hash: 'architecture/shared-responsibility', desc: 'Who secures what — IaaS vs PaaS vs SaaS' },
    { label: 'Cloud Provider Comparison', hash: 'framework/csp', desc: 'AWS, Azure, GCP, Alibaba, Huawei, Oracle — services and benchmarks' },
    { label: 'Identity & Access Management', hash: 'control/identity-access-management', desc: 'MFA, least privilege, federation, PAM' },
    { label: 'Known Cloud Incidents', hash: 'threats/incidents', desc: 'Capital One, SolarWinds, Snowflake, Storm-0558' },
    { label: 'Risk Register', hash: 'risk/register', desc: 'Cloud-specific risks with treatment strategies' },
  ];

  const cspCards = ['AWS', 'Azure', 'GCP', 'Alibaba', 'Huawei', 'Oracle'].map(c => {
    const id = c.toLowerCase();
    return `<div class="control-card" onclick="navigate('framework/csp-${id}')">
      <h3 class="control-card-title">${escHtml(c)}</h3>
      <div class="control-card-meta">${cspBadge(c)}</div>
    </div>`;
  }).join('');

  setApp(`
    <div class="disclaimer">
      <strong>Educational use only.</strong> CSA CCM content is paraphrased — obtain normative text from cloudsecurityalliance.org.
      CIS Benchmark checks are indicative — verify against official CIS publications. NACSA Act 854 references are indicative — verify against official Gazette.
    </div>

    <div class="page-title">Cloud Security Framework</div>
    <div class="page-sub">CSA CCM v4 · CIS Benchmarks · MITRE ATT&amp;CK Cloud · NIST CSF 2.0 · NACSA Act 854 (Malaysia)</div>

    <div class="stats-banner">
      <div class="stat-card"><div class="stat-number">${ccmDomainCount}</div><div class="stat-label">CCM Domains</div></div>
      <div class="stat-card"><div class="stat-number">197</div><div class="stat-label">CCM Controls</div></div>
      <div class="stat-card"><div class="stat-number">${domainCount}</div><div class="stat-label">Security Domains</div></div>
      <div class="stat-card"><div class="stat-number">${controlCount}</div><div class="stat-label">Controls</div></div>
      <div class="stat-card"><div class="stat-number">6</div><div class="stat-label">Cloud Providers</div></div>
      <div class="stat-card"><div class="stat-number">${incidentCount}</div><div class="stat-label">Incidents</div></div>
      <div class="stat-card"><div class="stat-number">${actorCount}</div><div class="stat-label">Threat Actors</div></div>
      <div class="stat-card"><div class="stat-number">${sectorCount}</div><div class="stat-label">Sectors</div></div>
    </div>

    <h2>Quick Start</h2>
    <div class="control-grid" style="margin-bottom:1.5rem">
      ${quickLinks.map(l => `
        <div class="control-card" onclick="navigate('${l.hash}')">
          <h3 class="control-card-title">${escHtml(l.label)}</h3>
          <p class="control-card-desc">${escHtml(l.desc)}</p>
        </div>`).join('')}
    </div>

    <h2>Cloud Providers</h2>
    <div class="control-grid" style="margin-bottom:1.5rem">${cspCards}</div>

    <h2>Key Cloud Incidents</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Incident</th><th>Year</th><th>Impact</th><th>Key Lesson</th></tr></thead>
      <tbody>
        ${incidents.incidents ? incidents.incidents.slice(0,6).map(i => `
          <tr><td><strong>${escHtml(i.name)}</strong></td><td>${escHtml(i.year)}</td><td style="font-size:0.75rem">${escHtml(i.impact)}</td><td style="font-size:0.75rem">${escHtml(i.keyLesson)}</td></tr>
        `).join('') : ''}
      </tbody>
    </table></div>

    <h2>NACSA Act 854 — Cloud NCII Obligations</h2>
    <div class="table-wrap"><table>
      <thead><tr><th>Section</th><th>Obligation</th><th>Cloud Framework Response</th></tr></thead>
      <tbody>
        <tr><td>${nacsaBadge(['s17'])}</td><td>NCII designation</td><td>Cloud asset inventory defines NCII scope including CSP-hosted assets</td></tr>
        <tr><td>${nacsaBadge(['s18'])}</td><td>Security measures</td><td>CSA CCM controls + CIS Benchmarks provide baseline security measures</td></tr>
        <tr><td>${nacsaBadge(['s21'])}</td><td>Risk assessment</td><td>Cloud risk methodology addresses shared responsibility, multi-tenancy, data sovereignty</td></tr>
        <tr><td>${nacsaBadge(['s22'])}</td><td>Code of practice</td><td>Sector-specific cloud requirements (BNM RMiT for financial)</td></tr>
        <tr><td>${nacsaBadge(['s23'])}</td><td>Security audit</td><td>CIS Benchmark automated assessments + CCM audit evidence</td></tr>
        <tr><td>${nacsaBadge(['s26'])}</td><td>Incident notification</td><td>Cloud IR plan with 6-hour NACSA notification procedure</td></tr>
      </tbody>
    </table></div>
  `);
}

// ─── FRAMEWORK (absorbs Standards, CIS, CSPs, RMiT Cloud) ───────────────────
async function renderFramework(sub, extra) {
  // Sub-routes for detail views
  if (sub === 'ccm-domains') return renderCCMDomains();
  if (sub === 'mitre-cloud') return renderMitreCloud();
  if (sub === 'nist-cloud') return renderNistCloud();
  if (sub && sub.startsWith('csp-')) return renderCSPDetail(sub.replace('csp-', ''), extra);
  if (sub === 'csp') return renderFramework(null, null); // show framework landing with CSP tab
  if (sub === 'cis') return renderFramework(null, null); // show framework landing with CIS tab
  if (sub === 'rmit') return renderRMiT(extra);

  // Framework landing with sub-tabs
  const [ccm, controls] = await Promise.all([
    load('standards/csa-ccm/control-domains.json'),
    load('controls/library.json'),
  ]);
  const ccmDomains = Array.isArray(ccm) ? ccm : (ccm.controlDomains || []);
  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);

  const tabs = [
    { key: 'ccm', label: `CCM Domains (${ccmDomains.length})` },
    { key: 'cis', label: 'CIS Benchmarks' },
    { key: 'csp', label: 'Cloud Providers' },
    { key: 'rmit', label: 'RMiT Cloud' },
  ];

  // CCM Domains table
  const ccmContent = `
    <div class="table-wrap"><table>
      <thead><tr><th>CCM Domain</th><th>Controls</th><th>NACSA</th><th>NIST CSF</th><th>MITRE</th></tr></thead>
      <tbody>
        ${ccmDomains.map(d => {
          const related = allControls.filter(c => (c.ccmControls || []).some(cc => cc.startsWith(d.id)));
          const nacsa = [...new Set(related.flatMap(c => c.nacsa || []))];
          const nist = [...new Set(related.flatMap(c => c.nistCsf || []))].slice(0, 3);
          const mitre = [...new Set(related.flatMap(c => c.mitreAttackCloud || []))].slice(0, 3);
          return `<tr>
            <td><a href="#framework/ccm-domains" style="text-decoration:none">${ccmBadge([d.id])} ${escHtml(d.name)}</a></td>
            <td>${related.length}</td>
            <td>${nacsa.length ? nacsaBadge(nacsa) : '-'}</td>
            <td style="font-size:0.75rem">${nist.length ? nist.map(n => `<span class="tag">${escHtml(n)}</span>`).join('') : '-'}</td>
            <td style="font-size:0.75rem">${mitre.length ? mitre.map(m => `<span class="badge badge-mandatory" style="font-size:0.6rem">${escHtml(m)}</span>`).join('') : '-'}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table></div>

    <div class="control-grid" style="margin-top:1rem">
      <div class="control-card" onclick="navigate('framework/mitre-cloud')">
        <h3 class="control-card-title">MITRE ATT&amp;CK Cloud</h3>
        <p class="control-card-desc">Cloud-specific adversary tactics and techniques</p>
      </div>
      <div class="control-card" onclick="navigate('framework/nist-cloud')">
        <h3 class="control-card-title">NIST Cloud Security Guidance</h3>
        <p class="control-card-desc">SP 800-144 and SP 800-210</p>
      </div>
    </div>
  `;

  // CIS Benchmarks
  const cisContent = `
    <p style="color:var(--text-secondary);margin-bottom:1rem">CIS Foundations Benchmarks for each cloud provider</p>
    <div class="control-grid">
      ${['AWS','Azure','GCP','Alibaba','Huawei','Oracle'].map(c => {
        const id = c.toLowerCase();
        return `<div class="control-card" onclick="navigate('framework/csp-${id}/benchmark')">
          <h3 class="control-card-title">CIS ${escHtml(c)} Benchmark</h3>
          <div class="control-card-meta">${cspBadge(c)}</div>
        </div>`;
      }).join('')}
    </div>
  `;

  // CSP landing
  const cspContent = `
    <p style="color:var(--text-secondary);margin-bottom:1rem">Security services, well-architected guidance for each CSP</p>
    <div class="control-grid">
      ${['AWS','Azure','GCP','Alibaba','Huawei','Oracle'].map(c => {
        const id = c.toLowerCase();
        const names = { aws:'Amazon Web Services', azure:'Microsoft Azure', gcp:'Google Cloud Platform', alibaba:'Alibaba Cloud', huawei:'Huawei Cloud', oracle:'Oracle Cloud (OCI)' };
        return `<div class="control-card" onclick="navigate('framework/csp-${id}')">
          <h3 class="control-card-title">${escHtml(names[id] || c)}</h3>
          <div class="control-card-meta">${cspBadge(c)}</div>
        </div>`;
      }).join('')}
    </div>
  `;

  // RMiT
  const rmitContent = `
    <p style="color:var(--text-secondary);margin-bottom:1rem">BNM RMiT cloud-specific clauses and CCM mapping</p>
    <div class="control-grid">
      <div class="control-card" onclick="navigate('framework/rmit')">
        <h3 class="control-card-title">RMiT Cloud Overview</h3>
        <p class="control-card-desc">Jurisdiction, applicability, cloud sections</p>
      </div>
      <div class="control-card" onclick="navigate('framework/rmit/clauses')">
        <h3 class="control-card-title">Browse Clauses</h3>
        <p class="control-card-desc">Cloud-specific clauses (10.50-10.52, 17.1-17.5)</p>
      </div>
      <div class="control-card" onclick="navigate('framework/rmit/ccm-mapping')">
        <h3 class="control-card-title">CCM v4 Mapping</h3>
        <p class="control-card-desc">How CCM controls satisfy RMiT obligations</p>
      </div>
    </div>
  `;

  setApp(`
    <div class="page-title">Framework</div>
    <div class="page-sub">CSA CCM v4 domains, CIS Benchmarks, Cloud Providers, RMiT Cloud</div>

    ${buildSubTabs(tabs, 0)}
    ${buildSubPanels(tabs, [ccmContent, cisContent, cspContent, rmitContent], 0)}
  `);
  initSubTabs();
}

async function renderCCMDomains() {
  const domains = await load('standards/csa-ccm/control-domains.json');
  const list = Array.isArray(domains) ? domains : (domains.controlDomains || []);

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><span class="current">CCM Domains</span></nav>
    <div class="page-title">CSA CCM v4 — Control Domains</div>
    <div class="page-sub">${list.length} control domains covering all aspects of cloud security</div>

    ${list.map(d => `
      <div class="control-card" style="border-left:3px solid var(--type-preventive);cursor:default">
        <div class="control-card-header">
          ${ccmBadge([d.id])}
          <span class="badge badge-artifacts">${d.controlCount || '?'} controls</span>
        </div>
        <h3 class="control-card-title">${escHtml(d.name)}</h3>
        <p class="control-card-desc">${escHtml(d.description || '')}</p>
        ${d.exampleControls ? `<div style="margin-top:0.75rem">${tagList(d.exampleControls.map(c => typeof c === 'string' ? c : c.id || c.name || JSON.stringify(c)))}</div>` : ''}
      </div>`).join('')}
  `);
}

async function renderMitreCloud() {
  const data = await load('standards/mitre-attack-cloud/techniques.json');
  const techniques = data.techniques || data || [];
  const tactics = [...new Set(techniques.map(t => t.tactic))].filter(Boolean);

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><span class="current">MITRE ATT&amp;CK Cloud</span></nav>
    <div class="page-title">MITRE ATT&amp;CK Cloud</div>
    <div class="page-sub">${techniques.length} cloud-specific techniques across ${tactics.length} tactics</div>

    <div class="domain-filter" id="mitre-filter">
      <button class="domain-pill active" data-domain="all">All (${techniques.length})</button>
      ${tactics.map(t => `<button class="domain-pill" data-domain="${escHtml(t)}">${escHtml(t)} (${techniques.filter(x=>x.tactic===t).length})</button>`).join('')}
    </div>

    <div id="mitre-list">
      ${techniques.map(t => `
        <div class="control-card mitre-card" data-tactic="${escHtml(t.tactic || '')}" style="cursor:default;margin-bottom:0.75rem">
          <div class="control-card-header">
            <span class="badge badge-mandatory">${escHtml(t.id)}</span>
            <span class="control-card-title" style="margin:0">${escHtml(t.name)}</span>
          </div>
          <p class="control-card-desc">${escHtml(t.description || '')}</p>
          ${t.subtechniques && t.subtechniques.length ? `
            <div style="margin-top:0.75rem;padding-left:1rem;border-left:2px solid var(--danger)">
              <div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Sub-techniques (${t.subtechniques.length})</div>
              ${t.subtechniques.map(st => `
                <div style="margin-bottom:0.5rem">
                  <span class="badge badge-category" style="font-size:0.65rem">${escHtml(st.id)}</span>
                  <strong style="font-size:var(--font-size-sm)">${escHtml(st.name)}</strong>
                  <div style="font-size:var(--font-size-xs);color:var(--text-secondary);margin-top:0.15rem">${escHtml(st.description || '')}</div>
                </div>`).join('')}
            </div>` : ''}
          ${t.platforms ? `<div style="margin-top:0.5rem">${tagList(t.platforms)}</div>` : ''}
          ${t.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(t.ccmControls)}</div>` : ''}
        </div>`).join('')}
    </div>
  `);

  document.getElementById('mitre-filter').addEventListener('click', (e) => {
    const pill = e.target.closest('.domain-pill');
    if (!pill) return;
    document.querySelectorAll('#mitre-filter .domain-pill').forEach(b => b.classList.remove('active'));
    pill.classList.add('active');
    const tactic = pill.dataset.domain;
    document.querySelectorAll('.mitre-card').forEach(c => {
      c.style.display = (tactic === 'all' || c.dataset.tactic === tactic) ? '' : 'none';
    });
  });
}

async function renderNistCloud() {
  const data = await load('standards/nist-cloud/index.json');

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><span class="current">NIST Cloud Security</span></nav>
    <div class="page-title">NIST Cloud Security Guidance</div>
    <div class="page-sub">${escHtml(data.title || 'NIST SP 800-144 and SP 800-210')}</div>

    <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:1rem">
      <p style="color:var(--text-secondary)">${escHtml(data.description || data.scope || '')}</p>
    </div>

    ${(data.publications || []).map(p => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <h3 style="font-size:var(--font-size-md);font-weight:600;margin-bottom:0.25rem">${escHtml(p.id || '')} — ${escHtml(p.title || '')}</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">${escHtml(p.description || '')}</p>
        ${p.keyRecommendations ? `
          <div style="margin-top:0.75rem">
            <div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Key Recommendations</div>
            <ul style="font-size:var(--font-size-sm);padding-left:1.25rem;color:var(--text-secondary)">
              ${p.keyRecommendations.map(r => `<li style="margin-bottom:0.2rem">${escHtml(r)}</li>`).join('')}
            </ul>
          </div>` : ''}
      </div>`).join('')}
  `);
}

// CSP detail
async function renderCSPDetail(cspId, extra) {
  if (extra === 'benchmark') return renderCSPBenchmark(cspId);

  const [info, services] = await Promise.all([
    load(`standards/csp/${cspId}/index.json`),
    load(`standards/csp/${cspId}/services.json`),
  ]);

  const svcList = services.services || services || [];
  const categories = [...new Set(svcList.map(s => s.category))].filter(Boolean);

  let benchmarkBtn = '';
  try {
    await load(`standards/csp/${cspId}/cis-benchmark.json`);
    benchmarkBtn = `<div class="control-card" onclick="navigate('framework/csp-${cspId}/benchmark')" style="margin-bottom:1rem;border-color:var(--accent)">
      <h3 class="control-card-title">CIS Benchmark</h3>
      <p class="control-card-desc">View CIS Foundations Benchmark checks for ${escHtml(cspId.toUpperCase())}</p>
    </div>`;
  } catch(e) {}

  let wellArchSection = '';
  try {
    const wa = await load(`standards/csp/${cspId}/well-architected.json`);
    const principles = wa.designPrinciples || [];
    const areas = wa.bestPracticeAreas || [];
    wellArchSection = `
      <h2 style="margin-top:1.5rem">Well-Architected Framework — Security Pillar</h2>
      <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--type-preventive);border-radius:var(--radius);padding:1rem;margin-bottom:1rem">
        <p style="color:var(--text-secondary)">${escHtml(wa.description || '')}</p>
        ${wa.url ? `<div style="margin-top:0.5rem;font-size:var(--font-size-sm)"><a href="${escHtml(wa.url)}" target="_blank" rel="noopener">${escHtml(wa.url)}</a></div>` : ''}
      </div>
      ${principles.length ? `<h3>Design Principles (${principles.length})</h3>
        ${principles.map(p => `<div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.25rem">${ccmBadge([p.id])}<strong>${escHtml(p.title)}</strong></div>
          <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">${escHtml(p.description || '')}</p>
        </div>`).join('')}` : ''}
      ${areas.length ? `<h3>Best Practice Areas (${areas.length})</h3>
        <div class="accordion">${areas.map(a => `
          <div class="accordion-item">
            <button class="accordion-trigger" aria-expanded="false">
              <span>${ccmBadge([a.id])} ${escHtml(a.title)}</span>
              <span class="accordion-icon">&#9660;</span>
            </button>
            <div class="accordion-content" role="region" hidden>
              <p style="color:var(--text-secondary);margin-bottom:0.75rem">${escHtml(a.description || '')}</p>
              ${(a.questions || []).map(q => `
                <div style="margin-bottom:0.75rem">
                  <div style="font-weight:600;font-size:var(--font-size-sm);margin-bottom:0.35rem"><code style="color:var(--type-preventive);margin-right:0.35rem">${escHtml(q.id)}</code>${escHtml(q.title)}</div>
                  ${(q.practices || []).length ? `<ul style="font-size:var(--font-size-sm);padding-left:1.25rem;color:var(--text-secondary)">${q.practices.map(p => `<li style="margin-bottom:0.2rem">${escHtml(p)}</li>`).join('')}</ul>` : ''}
                </div>`).join('')}
            </div>
          </div>`).join('')}
        </div>` : ''}
    `;
  } catch(e) {}

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><span class="current">${escHtml(info.name || cspId.toUpperCase())}</span></nav>
    <div class="page-title">${escHtml(info.name || cspId.toUpperCase())}</div>
    <div class="page-sub">${escHtml(info.description || '')}</div>

    ${benchmarkBtn}

    <h2>Security Services (${svcList.length})</h2>
    <div class="domain-filter" id="csp-svc-filter">
      <button class="domain-pill active" data-domain="all">All (${svcList.length})</button>
      ${categories.map(c => `<button class="domain-pill" data-domain="${escHtml(c)}">${escHtml(c)} (${svcList.filter(s=>s.category===c).length})</button>`).join('')}
    </div>

    <div id="csp-svc-list">
      ${svcList.map(s => `
        <div class="control-card csp-svc-card" data-category="${escHtml(s.category || '')}" style="cursor:default;margin-bottom:0.75rem">
          <div class="control-card-header">
            <span class="control-card-title" style="margin:0">${escHtml(s.name)}</span>
            <span class="badge badge-artifacts">${escHtml(s.category || '')}</span>
          </div>
          <p class="control-card-desc">${escHtml(s.description || '')}</p>
          ${s.ccmMapping ? `<div style="margin-top:0.5rem">${ccmBadge(Array.isArray(s.ccmMapping) ? s.ccmMapping : [s.ccmMapping])}</div>` : ''}
        </div>`).join('')}
    </div>

    ${wellArchSection}
  `);

  document.getElementById('csp-svc-filter').addEventListener('click', (e) => {
    const pill = e.target.closest('.domain-pill');
    if (!pill) return;
    document.querySelectorAll('#csp-svc-filter .domain-pill').forEach(b => b.classList.remove('active'));
    pill.classList.add('active');
    const cat = pill.dataset.domain;
    document.querySelectorAll('.csp-svc-card').forEach(c => {
      c.style.display = (cat === 'all' || c.dataset.category === cat) ? '' : 'none';
    });
  });
  initAccordions();
}

async function renderCSPBenchmark(cspId) {
  const data = await load(`standards/csp/${cspId}/cis-benchmark.json`);
  const sections = data.sections || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><a href="#framework/csp-${cspId}">${escHtml(cspId.toUpperCase())}</a><span class="sep">/</span><span class="current">CIS Benchmark</span></nav>
    <div class="page-title">${escHtml(data.title || `CIS ${cspId.toUpperCase()} Foundations Benchmark`)}</div>
    <div class="page-sub">${escHtml(data.version || '')} — ${sections.reduce((n,s) => n + (s.checks || []).length, 0)} checks</div>

    ${sections.map(s => `
      <h2>${escHtml(s.name || s.section)} (${(s.checks || []).length} checks)</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Check</th><th>Level</th><th>Auto</th></tr></thead>
        <tbody>
          ${(s.checks || []).map(c => `
            <tr>
              <td><code>${escHtml(c.id)}</code></td>
              <td>${escHtml(c.title)}</td>
              <td><span class="badge badge-${c.level === 1 ? 'artifacts' : 'mandatory'}">L${c.level}</span></td>
              <td>${c.automated ? '<span style="color:var(--success)">Yes</span>' : '<span style="color:var(--text-muted)">Manual</span>'}</td>
            </tr>`).join('')}
        </tbody>
      </table></div>
    `).join('')}
  `);
}

// RMiT Cloud sub-views
async function renderRMiT(sub) {
  if (sub === 'clauses') return renderRMiTClauses();
  if (sub === 'ccm-mapping') return renderRMiTCCMMapping();
  if (sub && sub.startsWith('clause-')) return renderRMiTClauseDetail(sub.replace('clause-', ''));

  const rmit = await load('standards/rmit-cloud/index.json');

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><span class="current">RMiT Cloud</span></nav>
    <div class="page-title">BNM RMiT — Cloud Requirements</div>
    <div class="page-sub">${escHtml(rmit.fullTitle || rmit.standard)}</div>

    <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--type-preventive);border-radius:var(--radius);padding:1rem;margin-bottom:1rem">
      <div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.5rem">Jurisdiction &amp; Applicability</div>
      <p style="color:var(--text-secondary)">${escHtml(rmit.jurisdiction || '')}</p>
      <p style="color:var(--text-secondary);margin-top:0.5rem">${escHtml(rmit.applicability || '')}</p>
    </div>

    <h2>Cloud-Specific Sections</h2>
    ${(rmit.cloudSections || []).map(s => `
      <div class="control-card" onclick="navigate('framework/rmit/clauses')" style="margin-bottom:0.75rem">
        <div class="control-card-header">${ccmBadge([s.id])}</div>
        <h3 class="control-card-title">${escHtml(s.name)}</h3>
        <p class="control-card-desc">${escHtml(s.description || '')}</p>
        <div class="control-card-meta">${(s.clauses || []).map(c => `<span class="badge badge-artifacts">${escHtml(c)}</span>`).join('')}</div>
      </div>`).join('')}

    <h2>Key Principles</h2>
    <ul style="padding-left:1.25rem;color:var(--text-secondary)">
      ${(rmit.keyPrinciples || []).map(p => `<li style="margin-bottom:0.35rem">${escHtml(p)}</li>`).join('')}
    </ul>

    ${rmit.cloudRelevantSections ? `
      <h2 style="margin-top:1.5rem">Cloud-Relevant Sections</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Section</th><th>Name</th><th>Relevance</th></tr></thead>
        <tbody>${(rmit.cloudRelevantSections || []).map(s => `
          <tr><td><span class="badge badge-artifacts">${escHtml(s.section)}</span></td><td>${escHtml(s.name)}</td><td style="color:var(--text-secondary)">${escHtml(s.relevance)}</td></tr>`).join('')}
        </tbody>
      </table></div>` : ''}

    <div class="control-grid" style="margin-top:1.5rem">
      <div class="control-card" onclick="navigate('framework/rmit/clauses')">
        <h3 class="control-card-title">Browse Clauses</h3>
        <p class="control-card-desc">Cloud-specific clauses with requirements and CSP guidance</p>
      </div>
      <div class="control-card" onclick="navigate('framework/rmit/ccm-mapping')">
        <h3 class="control-card-title">CCM v4 Mapping</h3>
        <p class="control-card-desc">How CCM controls satisfy RMiT cloud obligations</p>
      </div>
    </div>

    ${rmit.relatedRepo ? `
      <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--info);border-radius:var(--radius);padding:1rem;margin-top:1rem">
        <div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Full RMiT Compliance Database</div>
        <p style="color:var(--text-secondary)">${escHtml(rmit.relatedRepoDescription || '')}</p>
        <a href="${escHtml(rmit.relatedRepo)}" target="_blank" rel="noopener">${escHtml(rmit.relatedRepo)}</a>
      </div>` : ''}
  `);
}

async function renderRMiTClauses() {
  const data = await load('standards/rmit-cloud/clauses.json');
  const clauses = data.clauses || [];
  const markerColors = { S: 'var(--danger)', G: 'var(--warning)' };

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><a href="#framework/rmit">RMiT Cloud</a><span class="sep">/</span><span class="current">Clauses</span></nav>
    <div class="page-title">RMiT Cloud Clauses</div>
    <div class="page-sub">${clauses.length} cloud-specific clauses from BNM RMiT</div>

    ${data.verificationNote ? `<div class="disclaimer">${escHtml(data.verificationNote)}</div>` : ''}

    ${clauses.map(c => `
      <div class="control-card" onclick="navigate('framework/rmit/clause-${escHtml(c.id)}')" style="border-left:3px solid ${markerColors[c.marker] || 'var(--border)'};margin-bottom:0.75rem">
        <div class="control-card-header">
          <span class="badge" style="background:${markerColors[c.marker] || 'var(--surface-hover)'};color:#fff">${escHtml(c.id)}</span>
          <span class="badge badge-category">${escHtml(c.marker)} — ${escHtml(c.markerMeaning)}</span>
          <span class="badge badge-artifacts">${escHtml(c.clauseType)}</span>
        </div>
        <h3 class="control-card-title">${escHtml(c.title)}</h3>
        <p class="control-card-desc">${escHtml(c.summary)}</p>
      </div>`).join('')}
  `);
}

async function renderRMiTClauseDetail(clauseId) {
  const data = await load('standards/rmit-cloud/clauses.json');
  const clause = (data.clauses || []).find(c => c.id === clauseId);
  if (!clause) { setApp('<div class="error-state"><h2>Clause not found</h2><button onclick="navigate(\'framework/rmit/clauses\')">Back to Clauses</button></div>'); return; }

  const markerColors = { S: 'var(--danger)', G: 'var(--warning)' };
  let extra = '';

  if (clause.riskAreas) {
    extra += `<section class="detail-section"><h2 class="detail-section-title">Risk Assessment Areas</h2>
      ${clause.riskAreas.map(r => `<div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--type-preventive);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <strong>${escHtml(r.area)}</strong><p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(r.description)}</p>
        ${(r.ccmControls || []).length ? `<div style="margin-top:0.5rem">${ccmBadge(r.ccmControls)}</div>` : ''}
      </div>`).join('')}</section>`;
  }
  if (clause.appendix10Domains) {
    extra += `<section class="detail-section"><h2 class="detail-section-title">Appendix 10 Control Domains</h2>
      ${clause.appendix10Domains.map(d => `<div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--info);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <strong>${escHtml(d.domain)}</strong>
        <ul style="margin:0.5rem 0;padding-left:1.25rem">${(d.keyControls || []).map(k => `<li style="color:var(--text-secondary)">${escHtml(k)}</li>`).join('')}</ul>
        ${(d.ccmControls || []).length ? `<div style="margin-top:0.5rem">${ccmBadge(d.ccmControls)}</div>` : ''}
      </div>`).join('')}</section>`;
  }
  if (clause.requirements) {
    extra += `<section class="detail-section"><h2 class="detail-section-title">Requirements</h2>
      <ul style="padding-left:1.25rem">${clause.requirements.map(r => `<li style="color:var(--text-secondary);margin-bottom:0.35rem">${escHtml(r)}</li>`).join('')}</ul></section>`;
  }
  if (clause.cspRegionOptions) {
    extra += `<section class="detail-section"><h2 class="detail-section-title">CSP Data Residency Options</h2>
      <div class="table-wrap"><table><thead><tr><th>CSP</th><th>Malaysia Region</th><th>Nearest Approved</th><th>Notes</th></tr></thead><tbody>
        ${clause.cspRegionOptions.map(r => `<tr><td><strong>${escHtml(r.csp)}</strong></td><td>${escHtml(r.malaysiaRegion)}</td><td>${escHtml(r.nearestApproved)}</td><td style="color:var(--text-secondary)">${escHtml(r.notes)}</td></tr>`).join('')}
      </tbody></table></div></section>`;
  }
  if (clause.prerequisites) {
    extra += `<section class="detail-section"><h2 class="detail-section-title">Prerequisites</h2>
      ${clause.prerequisites.map(p => `<div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <span class="badge badge-artifacts">Step ${escHtml(p.step)}</span>
        <p style="color:var(--text-secondary);margin-top:0.25rem">${escHtml(p.requirement)}</p>
        ${(p.ccmControls || []).length ? `<div style="margin-top:0.5rem">${ccmBadge(p.ccmControls)}</div>` : ''}
      </div>`).join('')}</section>`;
  }
  if (clause.preconditions) {
    extra += `<section class="detail-section"><h2 class="detail-section-title">Preconditions</h2>
      <ul style="padding-left:1.25rem">${clause.preconditions.map(p => `<li style="color:var(--text-secondary);margin-bottom:0.35rem">${escHtml(p)}</li>`).join('')}</ul></section>`;
  }
  if (clause.cspGuidance) {
    const cspNames = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' };
    extra += `<section class="detail-section"><h2 class="detail-section-title">CSP Implementation Guidance</h2>
      ${Object.entries(clause.cspGuidance).map(([k, v]) => `<div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <strong>${escHtml(cspNames[k] || k)}</strong> ${cspBadge(cspNames[k] || k)}
        <p style="color:var(--text-secondary);margin-top:0.25rem">${escHtml(v)}</p>
      </div>`).join('')}</section>`;
  }

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><a href="#framework/rmit">RMiT</a><span class="sep">/</span><a href="#framework/rmit/clauses">Clauses</a><span class="sep">/</span><span class="current">${escHtml(clause.id)}</span></nav>

    <article class="control-detail">
      <header class="control-detail-header">
        <div class="control-detail-id-row">
          <span class="badge" style="background:${markerColors[clause.marker] || 'var(--surface-hover)'};color:#fff;font-size:var(--font-size-md);padding:0.35rem 0.75rem">${escHtml(clause.id)}</span>
          <span class="badge badge-category">${escHtml(clause.marker)} — ${escHtml(clause.markerMeaning)}</span>
          <span class="badge badge-artifacts">${escHtml(clause.clauseType)}</span>
          <span class="badge badge-artifacts">${escHtml(clause.section)}</span>
        </div>
        <h1 class="control-detail-title">${escHtml(clause.title)}</h1>
        <p class="control-detail-desc">${escHtml(clause.summary)}</p>
      </header>

      ${clause.higherRiskServices ? `<div class="disclaimer"><strong>Higher-Risk Services:</strong> ${escHtml(clause.higherRiskServices)}</div>` : ''}
      ${clause.keyConsideration ? `<div class="disclaimer"><strong>Key Consideration:</strong> ${escHtml(clause.keyConsideration)}</div>` : ''}
      ${clause.implication ? `<div class="disclaimer"><strong>Implication:</strong> ${escHtml(clause.implication)}</div>` : ''}

      ${extra}

      ${clause.evidence ? `<section class="detail-section"><h2 class="detail-section-title">Evidence Requirements</h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.375rem">${clause.evidence.map(e => `<span class="badge badge-category">${escHtml(e)}</span>`).join('')}</div></section>` : ''}

      ${clause.ccmControls ? `<section class="detail-section"><h2 class="detail-section-title">Mapped CCM Controls</h2>
        <div style="display:flex;flex-wrap:wrap;gap:0.375rem">${ccmBadge(clause.ccmControls)}</div></section>` : ''}
    </article>
  `);
}

async function renderRMiTCCMMapping() {
  const data = await load('standards/rmit-cloud/ccm-mapping.json');
  const mappings = data.mappings || [];
  const approach = data.complianceApproach || {};

  setApp(`
    <nav class="breadcrumbs"><a href="#framework">Framework</a><span class="sep">/</span><a href="#framework/rmit">RMiT</a><span class="sep">/</span><span class="current">CCM Mapping</span></nav>
    <div class="page-title">RMiT to CCM v4 Mapping</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${mappings.map(m => `
      <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--type-preventive);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
          <strong>${escHtml(m.rmitArea)}</strong>
          ${(m.rmitClauses || []).map(c => `<span class="badge badge-artifacts">${escHtml(c)}</span>`).join('')}
        </div>
        <p style="color:var(--text-secondary);margin-bottom:0.75rem">${escHtml(m.description)}</p>
        <div class="table-wrap"><table>
          <thead><tr><th>CCM Domain</th><th>Controls</th><th>Alignment</th></tr></thead>
          <tbody>${(m.ccmDomains || []).map(d => `
            <tr><td>${ccmBadge([d.domain])}</td><td>${(d.controls || []).map(c => `<span class="badge badge-category">${escHtml(c)}</span>`).join(' ')}</td><td style="color:var(--text-secondary)">${escHtml(d.alignment)}</td></tr>`).join('')}
          </tbody>
        </table></div>
      </div>`).join('')}

    ${approach.title ? `<h2 style="margin-top:1.5rem">${escHtml(approach.title)}</h2>
      <ol style="padding-left:1.25rem">${(approach.steps || []).map(s => `<li style="margin-bottom:0.5rem;color:var(--text-secondary)">${escHtml(s)}</li>`).join('')}</ol>` : ''}
  `);
}

// ─── CONTROLS ────────────────────────────────────────────────────────────────
async function renderControls() {
  const [domains, controls] = await Promise.all([
    load('controls/domains.json'),
    load('controls/library.json'),
  ]);

  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);
  const allDomains = Array.isArray(domains) ? domains : (domains.domains || []);

  setApp(`
    <div class="page-title">Control Library</div>
    <div class="page-sub">${allControls.length} controls across ${allDomains.length} domains</div>

    <div class="domain-filter" id="domain-filter">
      <button class="domain-pill active" data-domain="all">All (${allControls.length})</button>
      ${allDomains.map(d => {
        const count = allControls.filter(c => c.domain === d.id).length;
        return `<button class="domain-pill" data-domain="${escHtml(d.id)}">${escHtml(d.name)} (${count})</button>`;
      }).join('')}
    </div>

    <div class="control-grid" id="controls-grid">
      ${allControls.map(c => `
        <div class="control-card" onclick="navigate('control/${escHtml(c.slug || c.id)}')" data-domain="${escHtml(c.domain || '')}">
          <div class="control-card-header">
            <span class="control-id">${escHtml(c.id || c.slug || '')}</span>
            ${typeBadge(c.type)}
          </div>
          <h3 class="control-card-title">${escHtml(c.name)}</h3>
          <p class="control-card-desc">${escHtml(c.description || '')}</p>
          <div class="control-card-meta">
            ${c.ccmControls ? ccmBadge(c.ccmControls) : ''}
          </div>
        </div>`).join('')}
    </div>
  `);

  document.getElementById('domain-filter').addEventListener('click', (e) => {
    const pill = e.target.closest('.domain-pill');
    if (!pill) return;
    document.querySelectorAll('#domain-filter .domain-pill').forEach(b => b.classList.remove('active'));
    pill.classList.add('active');
    const domain = pill.dataset.domain;
    document.querySelectorAll('#controls-grid .control-card').forEach(c => {
      c.style.display = (domain === 'all' || c.dataset.domain === domain) ? '' : 'none';
    });
  });
}

// ─── CONTROL DETAIL — Auditor Flow ──────────────────────────────────────────
async function renderControlDetail(slug) {
  const [controls, artifactData, evidenceData] = await Promise.all([
    load('controls/library.json'),
    load('artifacts/inventory.json'),
    load('evidence/index.json'),
  ]);
  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);
  const ctrl = allControls.find(c => c.slug === slug || c.id === slug);
  if (!ctrl) { setApp('<div class="error-state"><h2>Control not found</h2><button onclick="navigate(\'controls\')">Back to Controls</button></div>'); return; }

  // Audit Package: artifacts
  const allArtifacts = Array.isArray(artifactData) ? artifactData : (artifactData.artifacts || []);
  const relatedArtifacts = allArtifacts.filter(a => (a.controlSlugs || []).includes(ctrl.slug || slug));

  // Audit Package: evidence
  const evidenceDomains = evidenceData.evidenceByDomain || evidenceData.domains || [];
  const domainEvidence = evidenceDomains.find(d => d.domainId === ctrl.domain || d.id === ctrl.domain);
  const relatedEvidence = domainEvidence ? (domainEvidence.items || []) : [];

  // Section 1: Requirements (3-column)
  const requirementsSection = `
    <section class="detail-section">
      <h2 class="detail-section-title">Requirements</h2>
      <div class="requirements-grid">
        <div class="requirement-block requirement-legal">
          <div class="requirement-block-label">Legal / Regulatory</div>
          <ul>
            ${ctrl.nacsa ? ctrl.nacsa.map(n => `<li>NACSA Act 854 ${escHtml(n)}</li>`).join('') : '<li>See framework mappings below</li>'}
          </ul>
        </div>
        <div class="requirement-block requirement-technical">
          <div class="requirement-block-label">Technical</div>
          <ul>
            <li>${escHtml(ctrl.description || 'Implement technical controls as specified')}</li>
            ${ctrl.cspImplementation ? Object.entries(ctrl.cspImplementation).slice(0,2).map(([k,v]) => `<li>${escHtml(k.toUpperCase())}: ${escHtml(v)}</li>`).join('') : ''}
          </ul>
        </div>
        <div class="requirement-block requirement-governance">
          <div class="requirement-block-label">Governance</div>
          <ul>
            <li>Policy approved and reviewed annually</li>
            <li>Exception process with time-bound approvals</li>
          </ul>
        </div>
      </div>
    </section>`;

  // Section 2: Key Activities
  const activitiesSection = ctrl.keyActivities ? `
    <section class="detail-section">
      <h2 class="detail-section-title">Key Activities</h2>
      <ul class="activity-list">
        ${ctrl.keyActivities.map(a => `<li>${escHtml(a)}</li>`).join('')}
      </ul>
    </section>` : '';

  // Section 3: Maturity Levels
  let maturitySection = '';
  if (ctrl.maturityLevels) {
    const levels = ctrl.maturityLevels;
    if (typeof levels === 'object' && !Array.isArray(levels)) {
      const entries = Object.entries(levels);
      maturitySection = `
        <section class="detail-section">
          <h2 class="detail-section-title">Maturity Levels</h2>
          <div class="maturity-grid">
            ${entries.map(([lvl, desc], i) => {
              const cls = i === 0 ? 'maturity-basic' : i === 1 ? 'maturity-mature' : 'maturity-advanced';
              const label = i === 0 ? 'Basic' : i === 1 ? 'Mature' : 'Advanced';
              return `<div class="maturity-card ${cls}"><div class="maturity-label">${label} (Level ${escHtml(lvl)})</div><p>${escHtml(desc)}</p></div>`;
            }).join('')}
          </div>
        </section>`;
    }
  }

  // Section 4: Audit Package
  let auditPackageSection = '';
  if (relatedEvidence.length || relatedArtifacts.length) {
    auditPackageSection = `
      <section class="audit-package">
        <h2 class="audit-package-title">
          Audit Package
          <span class="audit-package-counts">
            <span class="badge badge-evidence">${relatedEvidence.length} evidence items</span>
            <span class="badge badge-artifacts">${relatedArtifacts.length} artifacts</span>
          </span>
        </h2>

        <!-- 4a: Evidence Checklist -->
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-trigger" aria-expanded="true">
              <span>Evidence Checklist (${relatedEvidence.length})</span>
              <span class="accordion-icon">&#9660;</span>
            </button>
            <div class="accordion-content" role="region">
              ${relatedEvidence.length ? relatedEvidence.map(e => `
                <div class="evidence-item">
                  <div class="evidence-item-header">
                    ${e.id ? `<span class="evidence-id">${escHtml(e.id)}</span>` : ''}
                    <span class="evidence-item-name">${escHtml(e.name)}</span>
                  </div>
                  <p class="evidence-item-desc">${escHtml(e.description || '')}</p>
                  ${e.howToVerify ? `<p class="evidence-item-desc"><strong>How to verify:</strong> ${escHtml(e.howToVerify)}</p>` : ''}
                  ${(e.whatGoodLooksLike || e.commonGaps) ? `
                    <div class="evidence-detail-grid">
                      ${e.whatGoodLooksLike ? `<div class="evidence-block evidence-good">
                        <div class="evidence-block-label">What Good Looks Like</div>
                        <ul>${e.whatGoodLooksLike.map(w => `<li>${escHtml(w)}</li>`).join('')}</ul>
                      </div>` : ''}
                      ${e.commonGaps ? `<div class="evidence-block evidence-gap">
                        <div class="evidence-block-label">Common Gaps</div>
                        <ul>${e.commonGaps.map(g => `<li>${escHtml(g)}</li>`).join('')}</ul>
                      </div>` : ''}
                    </div>` : ''}
                </div>`).join('') : '<div class="empty-state"><p class="empty-state-text">No evidence items mapped to this control yet.</p></div>'}
            </div>
          </div>
        </div>

        <!-- 4b: Required Artifacts -->
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-trigger" aria-expanded="true">
              <span>Required Artifacts (${relatedArtifacts.length})</span>
              <span class="accordion-icon">&#9660;</span>
            </button>
            <div class="accordion-content" role="region">
              ${relatedArtifacts.length ? relatedArtifacts.map(a => `
                <div class="artifact-card">
                  <div class="artifact-card-header">
                    <span class="artifact-card-name">${escHtml(a.name)}</span>
                    <div class="artifact-card-badges">
                      ${a.mandatory !== undefined ? (a.mandatory ? '<span class="badge badge-mandatory">Mandatory</span>' : '<span class="badge badge-optional">Optional</span>') : ''}
                      ${a.format ? `<span class="badge badge-category">${escHtml(a.format)}</span>` : ''}
                    </div>
                  </div>
                  <p class="artifact-card-desc">${escHtml(a.description || '')}</p>
                  <div class="artifact-card-meta">
                    ${a.domain ? `<span class="meta-item"><strong>Domain:</strong> ${escHtml(a.domain)}</span>` : ''}
                    ${a.owner ? `<span class="meta-item"><strong>Owner:</strong> ${escHtml(a.owner)}</span>` : ''}
                    ${a.frequency ? `<span class="meta-item"><strong>Review:</strong> ${escHtml(a.frequency)}</span>` : ''}
                  </div>
                  ${a.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(a.ccmControls)}</div>` : ''}
                </div>`).join('') : '<div class="empty-state"><p class="empty-state-text">No artifacts mapped to this control yet.</p></div>'}
            </div>
          </div>
        </div>
      </section>`;
  }

  // Section 5: Framework Mappings
  const fwMappings = [];
  if (ctrl.nistCsf) fwMappings.push({ label: 'NIST CSF 2.0', codes: ctrl.nistCsf });
  if (ctrl.ccmControls) fwMappings.push({ label: 'CSA CCM v4', codes: ctrl.ccmControls });
  if (ctrl.nacsa) fwMappings.push({ label: 'NACSA Act 854', codes: ctrl.nacsa });
  if (ctrl.mitreAttackCloud) fwMappings.push({ label: 'MITRE ATT&CK Cloud', codes: ctrl.mitreAttackCloud });

  const fwSection = fwMappings.length ? `
    <section class="detail-section">
      <h2 class="detail-section-title">Framework Mappings</h2>
      <div class="fw-mappings">
        ${fwMappings.map(m => `
          <div class="fw-mapping-row">
            <span class="fw-label">${escHtml(m.label)}</span>
            <span class="fw-codes">${safeJoin(m.codes, ', ')}</span>
          </div>`).join('')}
      </div>
    </section>` : '';

  // Section 6: Source Provisions
  const provisionSection = ctrl.ccmControls ? `
    <section class="detail-section">
      <h2 class="detail-section-title">Source Provisions</h2>
      <div class="provision-links">
        ${ctrl.ccmControls.map(c => `
          <a href="#framework/ccm-domains" class="provision-link">
            <span class="provision-id">${escHtml(c)}</span>
            <span class="provision-title">CSA CCM v4 Control</span>
          </a>`).join('')}
        ${(ctrl.nacsa || []).map(n => `
          <a href="#reference/nacsa" class="provision-link">
            <span class="provision-id">${escHtml(n)}</span>
            <span class="provision-title">NACSA Act 854</span>
          </a>`).join('')}
      </div>
    </section>` : '';

  // CSP Implementation (extra, shown after source provisions)
  const cspSection = ctrl.cspImplementation ? `
    <section class="detail-section">
      <h2 class="detail-section-title">CSP Implementation</h2>
      ${Object.entries(ctrl.cspImplementation).map(([k, v]) => `
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
          <div style="margin-bottom:0.25rem">${cspBadge(k.toUpperCase())}</div>
          <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(v)}</p>
        </div>`).join('')}
    </section>` : '';

  setApp(`
    <article class="control-detail">
      <nav class="breadcrumbs">
        <a href="#controls">Controls</a>
        <span class="sep">/</span>
        <span class="current">${escHtml(ctrl.name)}</span>
      </nav>

      <header class="control-detail-header">
        <div class="control-detail-id-row">
          <span class="control-id">${escHtml(ctrl.id || ctrl.slug || '')}</span>
          ${typeBadge(ctrl.type)}
        </div>
        <h1 class="control-detail-title">${escHtml(ctrl.name)}</h1>
        <p class="control-detail-desc">${escHtml(ctrl.description || '')}</p>
      </header>

      ${requirementsSection}
      ${activitiesSection}
      ${maturitySection}
      ${auditPackageSection}
      ${fwSection}
      ${provisionSection}
      ${cspSection}
    </article>
  `);

  initAccordions();
}

// ─── RISK MANAGEMENT ─────────────────────────────────────────────────────────
async function renderRisk(sub) {
  if (sub === 'register') return renderRiskRegister();
  if (sub === 'methodology') return renderRiskMethodology();
  if (sub === 'checklist') return renderRiskChecklist();

  setApp(`
    <div class="page-title">Risk Management</div>
    <div class="page-sub">Cloud-specific risk assessment and treatment</div>

    ${buildSubTabs([
      { key: 'landing', label: 'Overview' },
      { key: 'methodology', label: 'Methodology' },
      { key: 'register', label: 'Risk Register' },
      { key: 'checklist', label: 'Checklist' },
    ], 0)}

    <div class="sub-panel active" data-subpanel="landing">
      <div class="control-grid">
        <div class="control-card" onclick="navigate('risk/methodology')">
          <h3 class="control-card-title">Risk Assessment Methodology</h3>
          <p class="control-card-desc">Cloud risk methodology aligned with ISO 27005 and NIST RMF</p>
        </div>
        <div class="control-card" onclick="navigate('risk/register')">
          <h3 class="control-card-title">Risk Register</h3>
          <p class="control-card-desc">Cloud-specific risks with ratings and treatment options</p>
        </div>
        <div class="control-card" onclick="navigate('risk/checklist')">
          <h3 class="control-card-title">Assessment Checklist</h3>
          <p class="control-card-desc">Cloud security assessment checklist by category</p>
        </div>
      </div>
    </div>
    <div class="sub-panel" data-subpanel="methodology"></div>
    <div class="sub-panel" data-subpanel="register"></div>
    <div class="sub-panel" data-subpanel="checklist"></div>
  `);

  initSubTabs();
  // Wire sub-tab clicks to navigate
  document.querySelectorAll('.sub-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.sub;
      if (key !== 'landing') navigate('risk/' + key);
    });
  });
}

async function renderRiskRegister() {
  const data = await load('risk-management/risk-register.json');
  const risks = data.risks || [];
  const categories = [...new Set(risks.map(r => r.category))].filter(Boolean);

  setApp(`
    <nav class="breadcrumbs"><a href="#risk">Risk Management</a><span class="sep">/</span><span class="current">Risk Register</span></nav>
    <div class="page-title">Cloud Risk Register</div>
    <div class="page-sub">${risks.length} cloud-specific risks</div>

    <div class="domain-filter" id="risk-filter">
      <button class="domain-pill active" data-domain="all">All (${risks.length})</button>
      ${categories.map(c => `<button class="domain-pill" data-domain="${escHtml(c)}">${escHtml(c)} (${risks.filter(r=>r.category===c).length})</button>`).join('')}
    </div>

    <div id="risk-list">
      ${risks.map(r => {
        const rating = (r.likelihood || 1) * (r.impact || 1);
        const ratingCls = rating >= 15 ? 'mandatory' : rating >= 10 ? 'mandatory' : rating >= 5 ? 'artifacts' : 'category';
        return `
          <div class="control-card risk-card" data-category="${escHtml(r.category || '')}" style="cursor:default;margin-bottom:0.75rem">
            <div class="control-card-header">
              <span class="badge badge-${ratingCls}">Risk: ${rating}</span>
              <h3 class="control-card-title" style="margin:0">${escHtml(r.title)}</h3>
            </div>
            <p class="control-card-desc">${escHtml(r.description || '')}</p>
            <div style="margin-top:0.5rem;font-size:var(--font-size-xs);color:var(--text-muted)">
              L:${r.likelihood} x I:${r.impact} · Treatment: <strong>${escHtml(r.treatmentOption || '')}</strong>
            </div>
            ${r.existingControls ? `<div style="margin-top:0.5rem">${tagList(r.existingControls)}</div>` : ''}
          </div>`;
      }).join('')}
    </div>
  `);

  document.getElementById('risk-filter').addEventListener('click', (e) => {
    const pill = e.target.closest('.domain-pill');
    if (!pill) return;
    document.querySelectorAll('#risk-filter .domain-pill').forEach(b => b.classList.remove('active'));
    pill.classList.add('active');
    const cat = pill.dataset.domain;
    document.querySelectorAll('.risk-card').forEach(c => {
      c.style.display = (cat === 'all' || c.dataset.category === cat) ? '' : 'none';
    });
  });
}

async function renderRiskMethodology() {
  const data = await load('risk-management/methodology.json');

  setApp(`
    <nav class="breadcrumbs"><a href="#risk">Risk Management</a><span class="sep">/</span><span class="current">Methodology</span></nav>
    <div class="page-title">${escHtml(data.title || 'Risk Assessment Methodology')}</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${(data.phases || (data.approach && data.approach.phases)) ? `
      <h2>Assessment Phases</h2>
      <div style="display:flex;flex-direction:column;gap:0.5rem">
        ${(data.phases || data.approach.phases).map((p, i) => `<div style="background:var(--surface);border-left:3px solid var(--type-preventive);border-radius:var(--radius-sm);padding:0.6rem 0.75rem;font-size:var(--font-size-sm)">
          <strong>Phase ${i+1}:</strong> ${escHtml(typeof p === 'string' ? p : p.name || p.title || JSON.stringify(p))}
        </div>`).join('')}
      </div>` : ''}

    ${data.cloudSpecificFactors ? `
      <h2 style="margin-top:1.5rem">Cloud-Specific Risk Factors</h2>
      ${(() => {
        const raw = Array.isArray(data.cloudSpecificFactors) ? data.cloudSpecificFactors : (data.cloudSpecificFactors.factors || [data.cloudSpecificFactors]);
        return tagList(raw.map(f => typeof f === 'string' ? f : f.name || f.title || JSON.stringify(f)));
      })()}` : ''}
  `);
}

async function renderRiskChecklist() {
  const data = await load('risk-management/checklist.json');
  const sections = data.sections || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#risk">Risk Management</a><span class="sep">/</span><span class="current">Checklist</span></nav>
    <div class="page-title">Cloud Security Assessment Checklist</div>
    <div class="page-sub">${sections.reduce((n,s) => n + (s.items || s.checks || []).length, 0)} checks across ${sections.length} categories</div>

    ${sections.map(s => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <h3 style="font-size:var(--font-size-md);font-weight:600;margin-bottom:0.5rem">${escHtml(s.name || s.section || '')}</h3>
        <ul style="font-size:var(--font-size-sm);padding-left:1.25rem">
          ${(s.checks || s.items || []).map(c => `<li style="margin-bottom:0.25rem;color:var(--text-secondary)">${escHtml(typeof c === 'string' ? c : c.item || c.check || c.title || JSON.stringify(c))}</li>`).join('')}
        </ul>
      </div>`).join('')}
  `);
}

// ─── THREATS ─────────────────────────────────────────────────────────────────
async function renderThreats(sub) {
  if (sub && sub !== 'incidents' && sub !== 'actors') return renderThreatDetail(sub);
  const activeTabIdx = sub === 'actors' ? 1 : 0;

  const [incidents, actors] = await Promise.all([
    load('threats/known-incidents.json'),
    load('threats/threat-actors.json'),
  ]);
  const incidentList = incidents.incidents || [];
  const actorList = actors.threatActors || [];

  const tabs = [
    { key: 'incidents', label: `Incidents (${incidentList.length})` },
    { key: 'actors', label: `Threat Actors (${actorList.length})` },
  ];

  setApp(`
    <div class="page-title">Cloud Threat Landscape</div>
    <div class="page-sub">Known incidents and threat actors targeting cloud environments</div>

    ${buildSubTabs(tabs, activeTabIdx)}

    <div class="sub-panel${activeTabIdx === 0 ? ' active' : ''}" data-subpanel="incidents">
      ${incidentList.map(i => `
        <div class="control-card" style="border-left:4px solid var(--danger);cursor:default;margin-bottom:0.75rem">
          <div class="control-card-header">
            <h3 class="control-card-title" style="margin:0;color:var(--danger)">${escHtml(i.name)}</h3>
            <span class="badge badge-mandatory">${escHtml(i.year)}</span>
            ${i.csp ? cspBadge(i.csp) : ''}
          </div>
          <p class="control-card-desc"><strong>Impact:</strong> ${escHtml(i.impact || '')}</p>
          <p class="control-card-desc"><strong>Root Cause:</strong> ${escHtml(i.rootCause || '')}</p>
          <p class="control-card-desc"><strong>Key Lesson:</strong> ${escHtml(i.keyLesson || '')}</p>
          ${i.killChain ? `
            <div style="margin-top:0.75rem">
              <div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Attack Chain</div>
              <div style="display:flex;flex-direction:column;gap:0.5rem">
                ${i.killChain.map((s,idx) => `<div style="background:var(--surface-hover);border-radius:var(--radius-sm);padding:0.6rem 0.75rem;font-size:var(--font-size-sm);border-left:3px solid var(--type-preventive)"><strong>Step ${idx+1}:</strong> ${escHtml(typeof s === 'string' ? s : s.action || s.description || JSON.stringify(s))}</div>`).join('')}
              </div>
            </div>` : ''}
          ${i.preventiveControls ? `<div style="margin-top:0.5rem">${ccmBadge(i.preventiveControls)}</div>` : ''}
        </div>`).join('')}
    </div>

    <div class="sub-panel${activeTabIdx === 1 ? ' active' : ''}" data-subpanel="actors">
      ${actorList.map(a => `
        <div class="control-card" style="border-left:3px solid var(--danger);cursor:default;margin-bottom:0.75rem">
          <h3 class="control-card-title">${escHtml(a.name)}</h3>
          ${a.aliases ? `<p style="font-size:var(--font-size-xs);color:var(--text-muted)">Also: ${escHtml(safeJoin(a.aliases))}</p>` : ''}
          <p class="control-card-desc"><strong>Motivation:</strong> ${escHtml(a.motivation || '')}</p>
          ${a.targetedCSPs ? `<div style="margin-top:0.5rem">${(Array.isArray(a.targetedCSPs) ? a.targetedCSPs : []).map(c => cspBadge(c)).join(' ')}</div>` : ''}
          ${a.typicalTTPs ? `<div style="margin-top:0.5rem">${tagList(a.typicalTTPs)}</div>` : ''}
          ${a.mitreTechniques ? `<div style="margin-top:0.5rem">${a.mitreTechniques.map(t => `<span class="badge badge-mandatory">${escHtml(t)}</span>`).join(' ')}</div>` : ''}
        </div>`).join('')}
    </div>
  `);
  initSubTabs();
}

// renderIncidents and renderActors handled inline by renderThreats with activeTabIdx

async function renderThreatDetail(id) {
  // For now, redirect to threats landing
  return renderThreats(null);
}

// ─── SECTORS ─────────────────────────────────────────────────────────────────
async function renderSectors() {
  const data = await load('sectors/index.json');
  const sectors = data.sectors || [];

  setApp(`
    <div class="page-title">Sectors</div>
    <div class="page-sub">Sector-specific cloud security requirements and regulatory obligations</div>

    <div class="control-grid">
      ${sectors.map(s => `
        <div class="control-card" onclick="navigate('sector/${escHtml(s.id)}')">
          <div class="control-card-header">
            <h3 class="control-card-title" style="margin:0">${escHtml(s.name)}</h3>
            <span class="badge badge-${s.cloudAdoption === 'high' ? 'mandatory' : s.cloudAdoption === 'medium' ? 'artifacts' : 'category'}">${escHtml(s.cloudAdoption || '')} adoption</span>
          </div>
          <p class="control-card-desc">${escHtml(s.description || '')}</p>
          ${s.regulatoryOverlap ? `<div style="margin-top:0.5rem">${tagList(s.regulatoryOverlap)}</div>` : ''}
        </div>`).join('')}
    </div>
  `);
}

async function renderSectorDetail(sectorId) {
  let data;
  try { data = await load(`sectors/requirements/${sectorId}.json`); }
  catch(e) {
    setApp(`<nav class="breadcrumbs"><a href="#sectors">Sectors</a><span class="sep">/</span><span class="current">${escHtml(sectorId)}</span></nav>
      <div class="empty-state"><p class="empty-state-text">Sector detail not yet available for ${escHtml(sectorId)}.</p></div>`);
    return;
  }

  const sector = (typeof data.sector === 'object' && data.sector) ? data.sector : data;
  const reqs = data.keyRequirements || data.requirements || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#sectors">Sectors</a><span class="sep">/</span><span class="current">${escHtml(data.sectorName || sector.name || sectorId)}</span></nav>
    <div class="page-title">${escHtml(data.sectorName || sector.name || sectorId)}</div>
    <div class="page-sub">${escHtml(sector.description || '')}</div>

    ${data.rmitSections ? `
      <h2>BNM RMiT Sections</h2>
      ${data.rmitSections.map(s => `
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
          <h3 style="font-size:var(--font-size-md);font-weight:600;margin-bottom:0.25rem">${escHtml(s.id || '')} — ${escHtml(s.title || '')}</h3>
          <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(s.description || '')}</p>
          ${s.cloudImplication ? `<p style="margin-top:0.5rem;font-size:var(--font-size-sm);color:var(--accent)"><strong>Cloud implication:</strong> ${escHtml(s.cloudImplication)}</p>` : ''}
        </div>`).join('')}
    ` : ''}

    <h2>Key Requirements</h2>
    ${reqs.map(r => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <h3 style="font-size:var(--font-size-md);font-weight:600;margin-bottom:0.25rem">${escHtml(r.title || r.name || '')}</h3>
        <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(r.description || '')}</p>
      </div>`).join('')}
  `);
}

// ─── ARCHITECTURE ────────────────────────────────────────────────────────────
async function renderArchitecture(sub) {
  if (sub === 'shared-responsibility') return renderSharedResp();
  if (sub === 'reference') return renderRefArch();
  if (sub === 'service-models') return renderServiceModels();
  if (sub === 'asset-types') return renderAssetTypes();
  if (sub === 'csp-comparison') return renderCSPComparisonArch();

  const tabs = [
    { key: 'service-models', label: 'Service Models' },
    { key: 'shared-responsibility', label: 'Shared Responsibility' },
    { key: 'reference', label: 'Reference Architecture' },
    { key: 'csp-comparison', label: 'CSP Comparison' },
  ];

  setApp(`
    <div class="page-title">Architecture</div>
    <div class="page-sub">Security architecture patterns for cloud environments</div>

    ${buildSubTabs(tabs, 0)}

    <div class="sub-panel active" data-subpanel="service-models">
      <div class="control-grid">
        <div class="control-card" onclick="navigate('architecture/service-models')">
          <h3 class="control-card-title">Service Models</h3>
          <p class="control-card-desc">IaaS / PaaS / SaaS / FaaS — security scope and key risks</p>
        </div>
        <div class="control-card" onclick="navigate('architecture/asset-types')">
          <h3 class="control-card-title">Cloud Asset Types</h3>
          <p class="control-card-desc">VMs, containers, serverless, storage — security profiles</p>
        </div>
      </div>
    </div>
    <div class="sub-panel" data-subpanel="shared-responsibility">
      <div class="control-card" onclick="navigate('architecture/shared-responsibility')" style="margin-bottom:0.75rem">
        <h3 class="control-card-title">Shared Responsibility Model</h3>
        <p class="control-card-desc">Who secures what — customer vs CSP across IaaS, PaaS, SaaS</p>
      </div>
    </div>
    <div class="sub-panel" data-subpanel="reference">
      <div class="control-card" onclick="navigate('architecture/reference')" style="margin-bottom:0.75rem">
        <h3 class="control-card-title">Reference Architecture</h3>
        <p class="control-card-desc">Multi-tier cloud security architecture layers</p>
      </div>
    </div>
    <div class="sub-panel" data-subpanel="csp-comparison">
      <div class="control-card" onclick="navigate('architecture/csp-comparison')" style="margin-bottom:0.75rem">
        <h3 class="control-card-title">CSP Service Comparison</h3>
        <p class="control-card-desc">Side-by-side security services across AWS, Azure, GCP, Alibaba, Huawei, Oracle</p>
      </div>
    </div>
  `);
  initSubTabs();
}

async function renderSharedResp() {
  const data = await load('architecture/shared-responsibility.json');
  const models = data.models || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#architecture">Architecture</a><span class="sep">/</span><span class="current">Shared Responsibility</span></nav>
    <div class="page-title">Shared Responsibility Model</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${data.malaysiaNexus ? `<div class="disclaimer">${escHtml(data.malaysiaNexus)}</div>` : ''}

    ${models.map(m => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <h3 style="font-size:var(--font-size-md);font-weight:600;margin-bottom:0.25rem">${escHtml(m.name)}</h3>
        <p style="font-size:var(--font-size-sm);color:var(--text-secondary)">${escHtml(m.description || '')}</p>
        <div class="requirements-grid" style="margin-top:0.75rem">
          <div class="requirement-block" style="background:var(--success-light);border-color:var(--success)">
            <div class="requirement-block-label" style="color:var(--success)">Customer Responsibility</div>
            <ul>${(m.customerResponsibility || []).map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
          </div>
          <div class="requirement-block" style="background:var(--info-light);border-color:var(--info)">
            <div class="requirement-block-label" style="color:var(--info)">CSP Responsibility</div>
            <ul>${(m.cspResponsibility || []).map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
          </div>
          ${m.sharedResponsibility ? `
            <div class="requirement-block" style="background:var(--warning-light);border-color:var(--warning)">
              <div class="requirement-block-label" style="color:var(--warning)">Shared</div>
              <ul>${m.sharedResponsibility.map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
            </div>` : ''}
        </div>
      </div>`).join('')}
  `);
}

async function renderRefArch() {
  const data = await load('architecture/reference-architecture.json');
  const tiers = data.tiers || data.layers || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#architecture">Architecture</a><span class="sep">/</span><span class="current">Reference Architecture</span></nav>
    <div class="page-title">Cloud Reference Architecture</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${tiers.map(t => `
      <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--type-preventive);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          ${ccmBadge([t.level || t.name])}
          <strong>${escHtml(t.name)}</strong>
        </div>
        <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(t.description || '')}</p>
        ${t.typicalComponents ? `<div style="margin-top:0.75rem">${tagList(t.typicalComponents.map(c => typeof c === 'string' ? c : c.type || c.name || JSON.stringify(c)))}</div>` : ''}
        ${t.securityCharacteristics ? `
          <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:var(--font-size-xs);color:var(--text-muted)">
            ${t.securityCharacteristics.primaryControls ? `<div><strong>Controls:</strong> ${escHtml(safeJoin(t.securityCharacteristics.primaryControls))}</div>` : ''}
            ${t.securityCharacteristics.vulnerabilities ? `<div style="margin-top:0.25rem"><strong>Vulnerabilities:</strong> ${escHtml(safeJoin(t.securityCharacteristics.vulnerabilities))}</div>` : ''}
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderServiceModels() {
  const data = await load('architecture/service-models.json');
  const models = data.serviceModels || data.models || data || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#architecture">Architecture</a><span class="sep">/</span><span class="current">Service Models</span></nav>
    <div class="page-title">Cloud Service Models</div>
    <div class="page-sub">Security scope and key risks for IaaS, PaaS, SaaS, and FaaS</div>

    ${(Array.isArray(models) ? models : []).map(m => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <h3 style="font-size:var(--font-size-md);font-weight:600;margin-bottom:0.25rem">${escHtml(m.name)}</h3>
        <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(m.description || '')}</p>
        ${m.examples ? `<div style="margin-top:0.5rem">${tagList(Array.isArray(m.examples) ? m.examples : (typeof m.examples === 'object' ? Object.values(m.examples).flat() : [m.examples]))}</div>` : ''}
        ${m.keyRisks ? `<div style="margin-top:0.75rem"><div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--danger);margin-bottom:0.35rem">Key Risks</div>
          <ul style="font-size:var(--font-size-sm);padding-left:1.25rem;color:var(--text-secondary)">${m.keyRisks.map(r => `<li>${escHtml(r)}</li>`).join('')}</ul></div>` : ''}
        ${m.keyControls ? `<div style="margin-top:0.5rem"><div style="font-size:var(--font-size-xs);text-transform:uppercase;color:var(--success);margin-bottom:0.35rem">Key Controls</div>
          <ul style="font-size:var(--font-size-sm);padding-left:1.25rem;color:var(--text-secondary)">${m.keyControls.map(c => `<li>${escHtml(c)}</li>`).join('')}</ul></div>` : ''}
      </div>`).join('')}
  `);
}

async function renderAssetTypes() {
  const data = await load('architecture/asset-types.json');
  const assets = data.assetTypes || data || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#architecture">Architecture</a><span class="sep">/</span><span class="current">Asset Types</span></nav>
    <div class="page-title">Cloud Asset Types</div>
    <div class="page-sub">${(Array.isArray(assets) ? assets : []).length} asset types with security profiles</div>

    ${(Array.isArray(assets) ? assets : []).map(a => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <strong>${escHtml(a.name)}</strong>
          <span class="badge badge-artifacts">${escHtml(a.category || '')}</span>
        </div>
        ${a.examples ? `<div style="margin-top:0.35rem">${tagList(Array.isArray(a.examples) ? a.examples : (typeof a.examples === 'object' ? Object.values(a.examples).flat() : [a.examples]))}</div>` : ''}
        ${a.securityProfile ? `
          <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:var(--font-size-xs);color:var(--text-muted)">
            ${a.securityProfile.keyRisks ? `<div><strong>Risks:</strong> ${escHtml(safeJoin(a.securityProfile.keyRisks))}</div>` : ''}
            ${a.securityProfile.compensatingControls ? `<div style="margin-top:0.25rem"><strong>Controls:</strong> ${escHtml(safeJoin(a.securityProfile.compensatingControls))}</div>` : ''}
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderCSPComparisonArch() {
  const data = await load('architecture/csp-comparison.json');
  const categories = data.categories || data || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#architecture">Architecture</a><span class="sep">/</span><span class="current">CSP Comparison</span></nav>
    <div class="page-title">CSP Service Comparison</div>
    <div class="page-sub">Side-by-side security services across cloud providers</div>

    <div class="table-wrap"><table>
      <thead><tr><th>Category</th><th>${cspBadge('AWS')}</th><th>${cspBadge('Azure')}</th><th>${cspBadge('GCP')}</th><th>${cspBadge('Alibaba')}</th><th>${cspBadge('Huawei')}</th><th>${cspBadge('Oracle')}</th></tr></thead>
      <tbody>
        ${(Array.isArray(categories) ? categories : []).map(c => `
          <tr>
            <td><strong>${escHtml(c.category)}</strong></td>
            <td style="font-size:var(--font-size-xs)">${escHtml(c.aws || '-')}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(c.azure || '-')}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(c.gcp || '-')}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(c.alibaba || '-')}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(c.huawei || '-')}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(c.oracle || '-')}</td>
          </tr>`).join('')}
      </tbody>
    </table></div>
  `);
}

// ─── REFERENCE (absorbs Cross-Refs + Framework mappings) ─────────────────────
async function renderReference(sub) {
  if (sub === 'nacsa') return renderCrossNacsa();
  if (sub === 'nist-csf') return renderCrossNistCsf();
  if (sub === 'mitre') return renderCrossMitre();
  if (sub === 'csp-mapping') return renderCrossCSP();
  if (sub === 'rmit-nacsa') return renderCrossRmitNacsa();

  setApp(`
    <div class="page-title">Reference</div>
    <div class="page-sub">Cross-framework mappings and bidirectional references</div>

    <div class="control-grid">
      <div class="control-card" onclick="navigate('reference/nacsa')">
        <h3 class="control-card-title">CCM v4 &rarr; NACSA Act 854</h3>
        <p class="control-card-desc">How CCM control domains align with Malaysian NCII obligations</p>
      </div>
      <div class="control-card" onclick="navigate('reference/rmit-nacsa')">
        <h3 class="control-card-title">BNM RMiT &rarr; NACSA Act 854</h3>
        <p class="control-card-desc">RMiT cloud clauses mapped to NACSA obligations</p>
      </div>
      <div class="control-card" onclick="navigate('reference/nist-csf')">
        <h3 class="control-card-title">CCM v4 &rarr; NIST CSF 2.0</h3>
        <p class="control-card-desc">CCM domains mapped to NIST functions and subcategories</p>
      </div>
      <div class="control-card" onclick="navigate('reference/mitre')">
        <h3 class="control-card-title">MITRE ATT&amp;CK Cloud &rarr; Controls</h3>
        <p class="control-card-desc">Cloud attack techniques mapped to defensive controls</p>
      </div>
      <div class="control-card" onclick="navigate('reference/csp-mapping')">
        <h3 class="control-card-title">CCM v4 &rarr; CSP Services</h3>
        <p class="control-card-desc">CCM domains mapped to AWS, Azure, and GCP services</p>
      </div>
    </div>
  `);
}

async function renderCrossNacsa() {
  const data = await load('cross-references/ccm-to-nacsa.json');
  const mappings = data.mappings || data || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#reference">Reference</a><span class="sep">/</span><span class="current">CCM &rarr; NACSA</span></nav>
    <div class="page-title">CCM v4 &rarr; NACSA Act 854</div>

    ${(Array.isArray(mappings) ? mappings : []).map(m => `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          ${ccmBadge([m.ccmDomain])}
          <strong>${escHtml(m.ccmDomainName || '')}</strong>
        </div>
        ${(m.nacsaSections || []).map(s => `
          <div style="padding:0.35rem 0;font-size:var(--font-size-sm);border-bottom:1px solid var(--border)">
            ${nacsaBadge([s.section])} <strong>${escHtml(s.title || '')}</strong>
            <div style="color:var(--text-secondary);margin-top:0.15rem">${escHtml(s.alignment || s.description || '')}</div>
          </div>`).join('')}
      </div>`).join('')}
  `);
}

async function renderCrossNistCsf() {
  const data = await load('cross-references/ccm-to-nist-csf.json');
  const mappings = data.mappings || data || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#reference">Reference</a><span class="sep">/</span><span class="current">CCM &rarr; NIST CSF</span></nav>
    <div class="page-title">CCM v4 &rarr; NIST CSF 2.0</div>

    <div class="table-wrap"><table>
      <thead><tr><th>CCM Domain</th><th>NIST CSF Subcategories</th></tr></thead>
      <tbody>
        ${(Array.isArray(mappings) ? mappings : []).map(m => `
          <tr>
            <td>${ccmBadge([m.ccmDomain])} ${escHtml(m.ccmDomainName || '')}</td>
            <td>${(m.nistCsfMappings || []).map(n => `<span class="tag">${escHtml(n)}</span>`).join(' ')}</td>
          </tr>`).join('')}
      </tbody>
    </table></div>
  `);
}

async function renderCrossMitre() {
  const data = await load('cross-references/mitre-to-controls.json');
  const mappings = data.mappings || data || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#reference">Reference</a><span class="sep">/</span><span class="current">MITRE &rarr; Controls</span></nav>
    <div class="page-title">MITRE ATT&amp;CK Cloud &rarr; Defensive Controls</div>

    <div class="table-wrap"><table>
      <thead><tr><th>Technique</th><th>CCM Controls</th><th>Detection Methods</th></tr></thead>
      <tbody>
        ${(Array.isArray(mappings) ? mappings : []).map(m => `
          <tr>
            <td><span class="badge badge-mandatory">${escHtml(m.techniqueId)}</span><br><span style="font-size:var(--font-size-xs)">${escHtml(m.techniqueName || '')}</span></td>
            <td>${(m.ccmControls || []).map(c => ccmBadge([c])).join(' ')}</td>
            <td style="font-size:var(--font-size-xs)">${(m.detectionMethods || []).map(d => `<span class="tag">${escHtml(d)}</span>`).join(' ')}</td>
          </tr>`).join('')}
      </tbody>
    </table></div>
  `);
}

async function renderCrossCSP() {
  const csps = ['aws', 'azure', 'gcp'];
  const results = await Promise.all(csps.map(c => load(`cross-references/ccm-to-${c}.json`).catch(() => null)));

  const data = {};
  csps.forEach((c, i) => { if (results[i]) data[c] = results[i].mappings || results[i] || []; });

  const allDomains = [...new Set(Object.values(data).flatMap(arr => (Array.isArray(arr) ? arr : []).map(m => m.ccmDomain)))];

  setApp(`
    <nav class="breadcrumbs"><a href="#reference">Reference</a><span class="sep">/</span><span class="current">CCM &rarr; CSP</span></nav>
    <div class="page-title">CCM v4 &rarr; CSP Services</div>

    <div class="table-wrap"><table>
      <thead><tr><th>CCM Domain</th><th>${cspBadge('AWS')}</th><th>${cspBadge('Azure')}</th><th>${cspBadge('GCP')}</th></tr></thead>
      <tbody>
        ${allDomains.map(d => {
          const get = (csp) => {
            const arr = data[csp] || [];
            const entry = (Array.isArray(arr) ? arr : []).find(m => m.ccmDomain === d);
            if (!entry) return '-';
            const svcArr = entry.services || entry.awsServices || entry.azureServices || entry.gcpServices || [];
            return safeJoin(svcArr.map(s => typeof s === 'string' ? s : s.service || s.name || JSON.stringify(s)));
          };
          return `<tr>
            <td>${ccmBadge([d])}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(get('aws'))}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(get('azure'))}</td>
            <td style="font-size:var(--font-size-xs)">${escHtml(get('gcp'))}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table></div>
  `);
}

async function renderCrossRmitNacsa() {
  const data = await load('cross-references/rmit-to-nacsa.json');
  const mappings = data.mappings || [];

  setApp(`
    <nav class="breadcrumbs"><a href="#reference">Reference</a><span class="sep">/</span><span class="current">RMiT &rarr; NACSA</span></nav>
    <div class="page-title">BNM RMiT &rarr; NACSA Act 854</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${data.verificationNote ? `<div class="disclaimer">${escHtml(data.verificationNote)}</div>` : ''}

    ${mappings.map(m => `
      <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--type-preventive);border-radius:var(--radius);padding:1rem;margin-bottom:0.75rem">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
          <span class="badge badge-mandatory">${escHtml(m.rmitClause)}</span>
          <strong>${escHtml(m.rmitTitle)}</strong>
          <span class="badge badge-artifacts">${escHtml(m.relationship)}</span>
        </div>
        <div style="margin-bottom:0.5rem">
          ${(m.nacsaSections || []).map(s => nacsaBadge([s])).join(' ')}
          <span style="font-size:var(--font-size-sm);color:var(--text-muted);margin-left:0.5rem">${escHtml(m.nacsaTitle || '')}</span>
        </div>
        <p style="color:var(--text-secondary);font-size:var(--font-size-sm)">${escHtml(m.notes || '')}</p>
      </div>`).join('')}
  `);
}

// ─── SEARCH ──────────────────────────────────────────────────────────────────
async function renderSearch(query) {
  const q = decodeURIComponent(query || '').toLowerCase();
  if (!q) { setApp('<div class="empty-state"><p class="empty-state-text">Enter a search term.</p></div>'); return; }

  const results = [];

  try {
    const controls = await load('controls/library.json');
    (Array.isArray(controls) ? controls : (controls.controls || [])).forEach(c => {
      if ([c.name, c.description, c.slug, c.id].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'Control', title: c.name, desc: c.description || '', hash: `control/${c.slug || c.id}` });
      }
    });
  } catch(e) {}

  try {
    const incidents = await load('threats/known-incidents.json');
    (incidents.incidents || []).forEach(i => {
      if ([i.name, i.impact, i.keyLesson, i.rootCause].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'Incident', title: i.name, desc: i.impact || '', hash: 'threats/incidents' });
      }
    });
  } catch(e) {}

  try {
    const actors = await load('threats/threat-actors.json');
    (actors.threatActors || []).forEach(a => {
      if ([a.name, a.motivation, ...(a.aliases||[])].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'Threat Actor', title: a.name, desc: a.motivation || '', hash: 'threats/actors' });
      }
    });
  } catch(e) {}

  try {
    const rmit = await load('standards/rmit-cloud/clauses.json');
    (rmit.clauses || []).forEach(c => {
      if ([c.id, c.title, c.summary, c.section, c.subsection].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'RMiT Clause', title: `${c.id} — ${c.title}`, desc: c.summary || '', hash: `framework/rmit/clause-${c.id}` });
      }
    });
  } catch(e) {}

  setApp(`
    <div class="page-title">Search Results</div>
    <div class="page-sub">${results.length} results for "${escHtml(query)}"</div>

    ${results.length ? results.map(r => `
      <div class="control-card" onclick="navigate('${escHtml(r.hash)}')" style="margin-bottom:0.75rem">
        <div class="control-card-header">
          <span class="badge badge-artifacts">${escHtml(r.type)}</span>
          <h3 class="control-card-title" style="margin:0">${escHtml(r.title)}</h3>
        </div>
        <p class="control-card-desc">${escHtml(r.desc)}</p>
      </div>`).join('') : '<div class="empty-state"><p class="empty-state-text">No results found.</p></div>'}
  `);
}

// ─── EXPORT ──────────────────────────────────────────────────────────────────
function exportToPDF() { window.print(); }

function exportToCSV() {
  const { view } = parseHash();
  let data = [];
  let filename = `export-${view}-${new Date().toISOString().slice(0,10)}.csv`;

  if (view === 'controls') {
    const list = cache.get('controls/library.json');
    if (list) {
      const controls = Array.isArray(list) ? list : (list.controls || []);
      data = controls.map(c => ({ ID: c.id || '', Name: c.name, Domain: c.domain, Description: (c.description || '').replace(/\n/g, ' ') }));
    }
  } else if (view === 'risk') {
    const reg = cache.get('risk-management/risk-register.json');
    if (reg) {
      const risks = reg.risks || [];
      data = risks.map(r => ({ ID: r.id || '', Risk: r.title, Impact: r.impact, Likelihood: r.likelihood, Category: r.category || '' }));
    }
  } else {
    alert('CSV export only supported for Controls and Risk Register views.');
    return;
  }

  if (!data.length) { alert('No data found to export.'); return; }

  const headers = Object.keys(data[0]);
  const csvContent = [
    headers.join(','),
    ...data.map(row => headers.map(h => `"${(row[h] || '').toString().replace(/"/g, '""')}"`).join(','))
  ].join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ─── INIT ────────────────────────────────────────────────────────────────────
window.navigate = navigate;

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', () => {
  // Wire export buttons without inline onclick
  const pdfBtn = document.getElementById('btn-pdf');
  const csvBtn = document.getElementById('btn-csv');
  if (pdfBtn) pdfBtn.addEventListener('click', exportToPDF);
  if (csvBtn) csvBtn.addEventListener('click', exportToCSV);

  route();

  const searchInput = document.getElementById('search-input');
  let debounce;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const q = searchInput.value.trim();
      if (q.length >= 2) navigate('search/' + encodeURIComponent(q));
    }, 400);
  });
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const q = searchInput.value.trim();
      if (q) navigate('search/' + encodeURIComponent(q));
    }
  });
});
