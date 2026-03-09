/* Cloud Security Framework — SPA v1.0
   Static, zero-dependency, hash-routed.
   Data loaded lazily and cached in Map.
*/

'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
const cache = new Map();
let currentView = null;
let currentSub  = null;

// ─── Data loader ─────────────────────────────────────────────────────────────
async function load(path) {
  if (cache.has(path)) return cache.get(path);
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to load ${path}: ${res.status}`);
  const data = await res.json();
  cache.set(path, data);
  return data;
}

// ─── Router ──────────────────────────────────────────────────────────────────
function parseHash() {
  const hash = location.hash.replace('#', '') || 'overview';
  const parts = hash.split('/');
  return { view: parts[0], sub: parts[1] || null };
}

function navigate(view, sub) {
  const hash = sub ? `#${view}/${sub}` : `#${view}`;
  history.pushState(null, '', hash);
  route();
}

async function route() {
  const { view, sub } = parseHash();
  currentView = view;
  currentSub  = sub;
  updateNav(view);
  const main = document.getElementById('main');
  main.innerHTML = '<div class="empty-state"><div class="empty-state-text">Loading...</div></div>';
  try {
    await render(view, sub);
  } catch (e) {
    main.innerHTML = `<div class="empty-state"><div class="empty-state-text">Error loading view.</div><div style="font-size:0.75rem;margin-top:0.5rem;color:var(--danger)">${e.message}</div></div>`;
    console.error(e);
  }
}

function updateNav(view) {
  document.querySelectorAll('.nav-link').forEach(el => {
    el.classList.toggle('active', el.dataset.view === view);
  });
}

// ─── Main dispatcher ─────────────────────────────────────────────────────────
async function render(view, sub) {
  switch (view) {
    case 'overview':        return renderOverview();
    case 'standards':       return renderStandards(sub);
    case 'architecture':    return renderArchitecture(sub);
    case 'csp':             return renderCSP(sub);
    case 'requirements':    return renderRequirements(sub);
    case 'controls':        return renderControls(sub);
    case 'evidence':        return renderEvidence(sub);
    case 'threats':         return renderThreats(sub);
    case 'sectors':         return renderSectors(sub);
    case 'cross-ref':       return renderCrossRef(sub);
    case 'framework':       return renderFramework(sub);
    case 'artifacts':       return renderArtifacts(sub);
    case 'risk-management': return renderRiskManagement(sub);
    case 'rmit':            return renderRMiT(sub);
    case 'search':          return renderSearch(sub);
    default:                return renderOverview();
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function setMain(html) { document.getElementById('main').innerHTML = html; }

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function tagList(arr) {
  if (!arr || !arr.length) return '';
  return `<div class="tag-list">${arr.map(t => `<span class="tag">${escHtml(t)}</span>`).join('')}</div>`;
}

function typeBadge(type) {
  if (!type) return '';
  const cls = { preventive:'preventive', detective:'detective', corrective:'corrective' }[type] || '';
  return `<span class="badge badge-${cls}">${escHtml(type)}</span>`;
}

function priorityBadge(p) {
  if (!p) return '';
  const cls = { critical:'critical', high:'high', medium:'medium', low:'low' }[p] || 'low';
  return `<span class="badge badge-${cls}">${escHtml(p)}</span>`;
}

function cspBadge(csp) {
  if (!csp) return '';
  const id = String(csp).toLowerCase().replace(/\s+/g,'-');
  const cls = { aws:'aws', azure:'azure', gcp:'gcp', alibaba:'alibaba', huawei:'huawei', oracle:'oracle' }[id] || '';
  return `<span class="badge badge-${cls}">${escHtml(csp)}</span>`;
}

function ccmBadge(codes) {
  if (!codes || !codes.length) return '';
  return (Array.isArray(codes) ? codes : [codes]).map(c => `<span class="badge badge-ccm">${escHtml(c)}</span>`).join(' ');
}

function nacsaBadge(codes) {
  if (!codes || !codes.length) return '';
  return codes.map(c => `<span class="badge badge-malaysia">${escHtml(c)}</span>`).join(' ');
}

function safeJoin(val, sep) {
  if (Array.isArray(val)) return val.join(sep || ', ');
  return String(val || '');
}

function cardClick(view, sub) {
  return `onclick="navigate('${view}','${sub}')" style="cursor:pointer"`;
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
    { icon: '&#9729;', label: 'CSA CCM v4 Control Domains', view: 'standards', sub: 'ccm-domains', desc: `${ccmDomainCount} domains — the primary cloud security framework` },
    { icon: '&#128274;', label: 'Shared Responsibility Model', view: 'architecture', sub: 'shared-responsibility', desc: 'Who secures what — IaaS vs PaaS vs SaaS' },
    { icon: '&#9881;', label: 'Cloud Provider Comparison', view: 'csp', sub: null, desc: 'AWS, Azure, GCP, Alibaba, Huawei, Oracle — services and benchmarks' },
    { icon: '&#128737;', label: 'Identity & Access Management', view: 'requirements', sub: 'identity-access-management', desc: 'MFA, least privilege, federation, PAM' },
    { icon: '&#128680;', label: 'Known Cloud Incidents', view: 'threats', sub: 'incidents', desc: 'Capital One, SolarWinds, Snowflake, Storm-0558' },
    { icon: '&#128200;', label: 'Risk Register', view: 'risk-management', sub: 'register', desc: 'Cloud-specific risks with treatment strategies' },
  ];

  const cspCards = ['AWS', 'Azure', 'GCP', 'Alibaba', 'Huawei', 'Oracle'].map(c => {
    const id = c.toLowerCase();
    return `<div class="card card-link csp-card ${id}" onclick="navigate('csp','${id}')">
      <div class="card-title">${escHtml(c)}</div>
      <div class="card-tags">${cspBadge(c)}</div>
    </div>`;
  }).join('');

  setMain(`
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
    <div class="two-col" style="margin-bottom:1.5rem">
      ${quickLinks.map(l => `
        <div class="card card-link" onclick="navigate('${l.view}','${l.sub || ''}')">
          <div class="card-title">${l.icon} ${escHtml(l.label)}</div>
          <div class="card-desc">${escHtml(l.desc)}</div>
        </div>`).join('')}
    </div>

    <h2>Cloud Providers</h2>
    <div class="three-col" style="margin-bottom:1.5rem">${cspCards}</div>

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
        <tr><td><span class="badge badge-malaysia">s17</span></td><td>NCII designation</td><td>Cloud asset inventory defines NCII scope including CSP-hosted assets</td></tr>
        <tr><td><span class="badge badge-malaysia">s18</span></td><td>Security measures</td><td>CSA CCM controls + CIS Benchmarks provide baseline security measures</td></tr>
        <tr><td><span class="badge badge-malaysia">s21</span></td><td>Risk assessment</td><td>Cloud risk methodology addresses shared responsibility, multi-tenancy, data sovereignty</td></tr>
        <tr><td><span class="badge badge-malaysia">s22</span></td><td>Code of practice</td><td>Sector-specific cloud requirements (BNM RMiT for financial)</td></tr>
        <tr><td><span class="badge badge-malaysia">s23</span></td><td>Security audit</td><td>CIS Benchmark automated assessments + CCM audit evidence</td></tr>
        <tr><td><span class="badge badge-malaysia">s26</span></td><td>Incident notification</td><td>Cloud IR plan with 6-hour NACSA notification procedure</td></tr>
      </tbody>
    </table></div>
  `);
}

// ─── STANDARDS ───────────────────────────────────────────────────────────────
async function renderStandards(sub) {
  if (sub === 'ccm-domains') return renderCCMDomains();
  if (sub === 'mitre-cloud') return renderMitreCloud();
  if (sub === 'nist-cloud') return renderNistCloud();

  const ccm = await load('standards/csa-ccm/index.json');

  setMain(`
    <div class="page-title">Standards &amp; Frameworks</div>
    <div class="page-sub">Primary cloud security standards referenced throughout this framework</div>

    <div class="card card-link" onclick="navigate('standards','ccm-domains')">
      <div class="card-title">CSA Cloud Controls Matrix v4</div>
      <div class="card-desc">${escHtml(ccm.scope || '17 control domains, 197 controls — the primary cloud security framework')}</div>
      <div class="card-tags"><span class="badge badge-ccm">PRIMARY</span></div>
    </div>

    <div class="card card-link" onclick="navigate('standards','mitre-cloud')">
      <div class="card-title">MITRE ATT&amp;CK Cloud</div>
      <div class="card-desc">Cloud-specific adversary tactics and techniques for AWS, Azure, GCP, and SaaS platforms</div>
      <div class="card-tags"><span class="badge badge-critical">THREAT INTEL</span></div>
    </div>

    <div class="card card-link" onclick="navigate('standards','nist-cloud')">
      <div class="card-title">NIST Cloud Security Guidance</div>
      <div class="card-desc">NIST SP 800-144 (Cloud Computing Guidelines) and SP 800-210 (Cloud Access Control)</div>
      <div class="card-tags"><span class="badge badge-medium">GUIDANCE</span></div>
    </div>
  `);
}

async function renderCCMDomains() {
  const domains = await load('standards/csa-ccm/control-domains.json');

  setMain(`
    <button class="back-link" onclick="navigate('standards')">&#8592; Standards</button>
    <div class="page-title">CSA CCM v4 — Control Domains</div>
    <div class="page-sub">17 control domains covering all aspects of cloud security</div>

    ${(Array.isArray(domains) ? domains : (domains.controlDomains || [])).map(d => `
      <div class="card" style="border-left:3px solid var(--accent2)">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span class="badge badge-ccm">${escHtml(d.id)}</span>
          <span class="card-title" style="margin:0">${escHtml(d.name)}</span>
          <span class="badge badge-medium">${d.controlCount || '?'} controls</span>
        </div>
        <div class="card-desc">${escHtml(d.description || '')}</div>
        ${d.exampleControls ? `
          <div style="margin-top:0.75rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Example Controls</div>
            ${tagList(d.exampleControls.map(c => typeof c === 'string' ? c : c.id || c.name || JSON.stringify(c)))}
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderMitreCloud() {
  const data = await load('standards/mitre-attack-cloud/techniques.json');
  const techniques = data.techniques || data || [];

  const tactics = [...new Set(techniques.map(t => t.tactic))].filter(Boolean);

  setMain(`
    <button class="back-link" onclick="navigate('standards')">&#8592; Standards</button>
    <div class="page-title">MITRE ATT&amp;CK Cloud</div>
    <div class="page-sub">${techniques.length} cloud-specific techniques across ${tactics.length} tactics</div>

    <div class="tabs" id="mitre-tabs">
      <button class="tab-btn active" onclick="filterMitre('all')">All (${techniques.length})</button>
      ${tactics.map(t => `<button class="tab-btn" onclick="filterMitre('${t}')">${escHtml(t)} (${techniques.filter(x=>x.tactic===t).length})</button>`).join('')}
    </div>

    <div id="mitre-list">
      ${techniques.map(t => `
        <div class="card mitre-card" data-tactic="${escHtml(t.tactic || '')}">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
            <span class="badge badge-critical">${escHtml(t.id)}</span>
            <span class="card-title" style="margin:0">${escHtml(t.name)}</span>
          </div>
          <div class="card-desc">${escHtml(t.description || '')}</div>
          ${t.subtechniques && t.subtechniques.length ? `
            <div style="margin-top:0.75rem;padding-left:1rem;border-left:2px solid var(--danger)">
              <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Sub-techniques (${t.subtechniques.length})</div>
              ${t.subtechniques.map(st => `
                <div style="margin-bottom:0.5rem">
                  <div style="display:flex;align-items:center;gap:0.5rem">
                    <span class="badge badge-high" style="font-size:0.65rem">${escHtml(st.id)}</span>
                    <strong style="font-size:0.8rem">${escHtml(st.name)}</strong>
                  </div>
                  <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.15rem">${escHtml(st.description || '')}</div>
                </div>`).join('')}
            </div>` : ''}
          ${t.platforms ? `<div style="margin-top:0.5rem">${tagList(t.platforms)}</div>` : ''}
          ${t.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(t.ccmControls)}</div>` : ''}
        </div>`).join('')}
    </div>
  `);
}

async function renderNistCloud() {
  const data = await load('standards/nist-cloud/index.json');

  setMain(`
    <button class="back-link" onclick="navigate('standards')">&#8592; Standards</button>
    <div class="page-title">NIST Cloud Security Guidance</div>
    <div class="page-sub">${escHtml(data.title || 'NIST SP 800-144 and SP 800-210')}</div>

    <div class="card">
      <div class="card-desc">${escHtml(data.description || data.scope || '')}</div>
    </div>

    ${(data.publications || []).map(p => `
      <div class="card">
        <div class="card-title">${escHtml(p.id || '')} — ${escHtml(p.title || '')}</div>
        <div class="card-desc">${escHtml(p.description || '')}</div>
        ${p.keyRecommendations ? `
          <div style="margin-top:0.75rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Key Recommendations</div>
            <ul style="font-size:0.8rem;padding-left:1.25rem;color:var(--text-muted)">
              ${p.keyRecommendations.map(r => `<li style="margin-bottom:0.2rem">${escHtml(r)}</li>`).join('')}
            </ul>
          </div>` : ''}
      </div>`).join('')}
  `);
}

// global filter for MITRE techniques
window.filterMitre = function(tactic) {
  document.querySelectorAll('#mitre-tabs .tab-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.mitre-card').forEach(c => {
    c.style.display = (tactic === 'all' || c.dataset.tactic === tactic) ? '' : 'none';
  });
};

// ─── ARCHITECTURE ────────────────────────────────────────────────────────────
async function renderArchitecture(sub) {
  if (sub === 'shared-responsibility') return renderSharedResp();
  if (sub === 'reference') return renderRefArch();
  if (sub === 'service-models') return renderServiceModels();
  if (sub === 'asset-types') return renderAssetTypes();
  if (sub === 'csp-comparison') return renderCSPComparison();

  setMain(`
    <div class="page-title">Cloud Architecture</div>
    <div class="page-sub">Security architecture patterns for cloud environments</div>

    <div class="card card-link" onclick="navigate('architecture','shared-responsibility')">
      <div class="card-title">Shared Responsibility Model</div>
      <div class="card-desc">Who secures what — customer vs CSP responsibilities across IaaS, PaaS, SaaS</div>
    </div>
    <div class="card card-link" onclick="navigate('architecture','reference')">
      <div class="card-title">Reference Architecture</div>
      <div class="card-desc">Multi-tier cloud security architecture — edge, compute, data, identity, network, management layers</div>
    </div>
    <div class="card card-link" onclick="navigate('architecture','service-models')">
      <div class="card-title">Service Models</div>
      <div class="card-desc">IaaS / PaaS / SaaS / FaaS — security scope and key risks for each model</div>
    </div>
    <div class="card card-link" onclick="navigate('architecture','asset-types')">
      <div class="card-title">Cloud Asset Types</div>
      <div class="card-desc">VMs, containers, serverless, storage, databases, networking — security profiles</div>
    </div>
    <div class="card card-link" onclick="navigate('architecture','csp-comparison')">
      <div class="card-title">CSP Service Comparison</div>
      <div class="card-desc">Side-by-side security service comparison across AWS, Azure, GCP, Alibaba, Huawei, Oracle</div>
    </div>
  `);
}

async function renderSharedResp() {
  const data = await load('architecture/shared-responsibility.json');
  const models = data.models || [];

  setMain(`
    <button class="back-link" onclick="navigate('architecture')">&#8592; Architecture</button>
    <div class="page-title">Shared Responsibility Model</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${data.malaysiaNexus ? `<div class="disclaimer">${escHtml(data.malaysiaNexus)}</div>` : ''}

    ${models.map(m => `
      <div class="card">
        <div class="card-title">${escHtml(m.name)}</div>
        <div class="card-desc">${escHtml(m.description || '')}</div>
        <div class="two-col" style="margin-top:0.75rem">
          <div>
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--success);margin-bottom:0.35rem">Customer Responsibility</div>
            <ul style="font-size:0.8rem;padding-left:1.25rem">${(m.customerResponsibility || []).map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
          </div>
          <div>
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--accent);margin-bottom:0.35rem">CSP Responsibility</div>
            <ul style="font-size:0.8rem;padding-left:1.25rem">${(m.cspResponsibility || []).map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
          </div>
        </div>
        ${m.sharedResponsibility ? `
          <div style="margin-top:0.5rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--warning);margin-bottom:0.35rem">Shared</div>
            ${tagList(m.sharedResponsibility)}
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderRefArch() {
  const data = await load('architecture/reference-architecture.json');
  const tiers = data.tiers || data.layers || [];

  setMain(`
    <button class="back-link" onclick="navigate('architecture')">&#8592; Architecture</button>
    <div class="page-title">Cloud Reference Architecture</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${tiers.map(t => `
      <div class="card" style="border-left:3px solid var(--accent2)">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span class="badge badge-ccm">${escHtml(t.level || t.name)}</span>
          <span class="card-title" style="margin:0">${escHtml(t.name)}</span>
        </div>
        <div class="card-desc">${escHtml(t.description || '')}</div>
        ${t.typicalComponents ? `
          <div style="margin-top:0.75rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Components</div>
            ${tagList(t.typicalComponents.map(c => typeof c === 'string' ? c : c.type || c.name || JSON.stringify(c)))}
          </div>` : ''}
        ${t.securityCharacteristics ? `
          <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--text-muted)">
            ${t.securityCharacteristics.primaryControls ? `<div><strong>Controls:</strong> ${escHtml(safeJoin(t.securityCharacteristics.primaryControls))}</div>` : ''}
            ${t.securityCharacteristics.vulnerabilities ? `<div style="margin-top:0.25rem"><strong>Vulnerabilities:</strong> ${escHtml(safeJoin(t.securityCharacteristics.vulnerabilities))}</div>` : ''}
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderServiceModels() {
  const data = await load('architecture/service-models.json');
  const models = data.models || data || [];

  setMain(`
    <button class="back-link" onclick="navigate('architecture')">&#8592; Architecture</button>
    <div class="page-title">Cloud Service Models</div>
    <div class="page-sub">Security scope and key risks for IaaS, PaaS, SaaS, and FaaS</div>

    ${(Array.isArray(models) ? models : []).map(m => `
      <div class="card">
        <div class="card-title">${escHtml(m.name)}</div>
        <div class="card-desc">${escHtml(m.description || '')}</div>
        ${m.examples ? `<div style="margin-top:0.5rem">${tagList(Array.isArray(m.examples) ? m.examples : [m.examples])}</div>` : ''}
        ${m.keyRisks ? `
          <div style="margin-top:0.75rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--danger);margin-bottom:0.35rem">Key Risks</div>
            <ul style="font-size:0.8rem;padding-left:1.25rem;color:var(--text-muted)">${m.keyRisks.map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
          </div>` : ''}
        ${m.keyControls ? `
          <div style="margin-top:0.5rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--success);margin-bottom:0.35rem">Key Controls</div>
            <ul style="font-size:0.8rem;padding-left:1.25rem;color:var(--text-muted)">${m.keyControls.map(c => `<li>${escHtml(c)}</li>`).join('')}</ul>
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderAssetTypes() {
  const data = await load('architecture/asset-types.json');
  const assets = data.assetTypes || data || [];

  setMain(`
    <button class="back-link" onclick="navigate('architecture')">&#8592; Architecture</button>
    <div class="page-title">Cloud Asset Types</div>
    <div class="page-sub">${(Array.isArray(assets) ? assets : []).length} asset types with security profiles</div>

    ${(Array.isArray(assets) ? assets : []).map(a => `
      <div class="card">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span class="card-title" style="margin:0">${escHtml(a.name)}</span>
          <span class="badge badge-medium">${escHtml(a.category || '')}</span>
        </div>
        ${a.examples ? `<div style="margin-top:0.35rem">${tagList(Array.isArray(a.examples) ? a.examples : [a.examples])}</div>` : ''}
        ${a.securityProfile ? `
          <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem;color:var(--text-muted)">
            ${a.securityProfile.keyRisks ? `<div><strong>Risks:</strong> ${escHtml(safeJoin(a.securityProfile.keyRisks))}</div>` : ''}
            ${a.securityProfile.compensatingControls ? `<div style="margin-top:0.25rem"><strong>Controls:</strong> ${escHtml(safeJoin(a.securityProfile.compensatingControls))}</div>` : ''}
          </div>` : ''}
      </div>`).join('')}
  `);
}

async function renderCSPComparison() {
  const data = await load('architecture/csp-comparison.json');
  const categories = data.categories || data || [];

  setMain(`
    <button class="back-link" onclick="navigate('architecture')">&#8592; Architecture</button>
    <div class="page-title">CSP Service Comparison</div>
    <div class="page-sub">Side-by-side security services across cloud providers</div>

    <div class="table-wrap"><table>
      <thead><tr><th>Category</th><th>${cspBadge('AWS')}</th><th>${cspBadge('Azure')}</th><th>${cspBadge('GCP')}</th><th>${cspBadge('Alibaba')}</th><th>${cspBadge('Huawei')}</th><th>${cspBadge('Oracle')}</th></tr></thead>
      <tbody>
        ${(Array.isArray(categories) ? categories : []).map(c => `
          <tr>
            <td><strong>${escHtml(c.category)}</strong></td>
            <td style="font-size:0.75rem">${escHtml(c.aws || '-')}</td>
            <td style="font-size:0.75rem">${escHtml(c.azure || '-')}</td>
            <td style="font-size:0.75rem">${escHtml(c.gcp || '-')}</td>
            <td style="font-size:0.75rem">${escHtml(c.alibaba || '-')}</td>
            <td style="font-size:0.75rem">${escHtml(c.huawei || '-')}</td>
            <td style="font-size:0.75rem">${escHtml(c.oracle || '-')}</td>
          </tr>`).join('')}
      </tbody>
    </table></div>
  `);
}

// ─── CLOUD PROVIDERS ─────────────────────────────────────────────────────────
async function renderCSP(sub) {
  const csps = ['aws','azure','gcp','alibaba','huawei','oracle'];

  if (sub && csps.includes(sub)) return renderCSPDetail(sub);
  if (sub && sub.endsWith('-benchmark')) return renderCSPBenchmark(sub.replace('-benchmark',''));

  setMain(`
    <div class="page-title">Cloud Providers</div>
    <div class="page-sub">Security services, CIS benchmarks, and well-architected guidance for each CSP</div>

    <div class="two-col">
      ${csps.map(id => {
        const name = { aws:'Amazon Web Services', azure:'Microsoft Azure', gcp:'Google Cloud Platform', alibaba:'Alibaba Cloud', huawei:'Huawei Cloud', oracle:'Oracle Cloud (OCI)' }[id];
        return `<div class="card card-link csp-card ${id}" onclick="navigate('csp','${id}')">
          <div class="card-title">${escHtml(name)}</div>
          <div class="card-tags">${cspBadge(id)}</div>
        </div>`;
      }).join('')}
    </div>
  `);
}

async function renderCSPDetail(cspId) {
  const [info, services] = await Promise.all([
    load(`standards/csp/${cspId}/index.json`),
    load(`standards/csp/${cspId}/services.json`),
  ]);

  const svcList = services.services || services || [];
  const categories = [...new Set(svcList.map(s => s.category))].filter(Boolean);

  let benchmarkBtn = '';
  try {
    await load(`standards/csp/${cspId}/cis-benchmark.json`);
    benchmarkBtn = `<div class="card card-link" onclick="navigate('csp','${cspId}-benchmark')" style="margin-bottom:1rem;background:rgba(56,189,248,0.05);border-color:var(--accent)">
      <div class="card-title">CIS Benchmark</div>
      <div class="card-desc">View CIS Foundations Benchmark checks for ${escHtml(cspId.toUpperCase())}</div>
    </div>`;
  } catch(e) { /* no benchmark file */ }

  // Well-Architected framework (only AWS, Azure, GCP have data)
  let wellArchSection = '';
  try {
    const wa = await load(`standards/csp/${cspId}/well-architected.json`);
    const principles = wa.designPrinciples || [];
    const areas = wa.bestPracticeAreas || [];

    wellArchSection = `
      <h2>Well-Architected Framework — Security Pillar</h2>
      <div class="card" style="border-left:3px solid var(--accent2);margin-bottom:1rem">
        <div class="card-desc">${escHtml(wa.description || '')}</div>
        ${wa.url ? `<div style="margin-top:0.5rem;font-size:0.8rem"><a href="${escHtml(wa.url)}" target="_blank" rel="noopener">${escHtml(wa.url)}</a></div>` : ''}
      </div>

      ${principles.length ? `
        <h3>Design Principles (${principles.length})</h3>
        ${principles.map(p => `
          <div class="card">
            <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.25rem">
              <span class="badge badge-ccm">${escHtml(p.id)}</span>
              <span class="card-title" style="margin:0">${escHtml(p.title)}</span>
            </div>
            <div class="card-desc">${escHtml(p.description || '')}</div>
          </div>`).join('')}
      ` : ''}

      ${areas.length ? `
        <h3>Best Practice Areas (${areas.length})</h3>
        ${areas.map(a => `
          <div class="accordion-item" onclick="this.classList.toggle('open')">
            <div class="accordion-header">
              <span><span class="badge badge-medium" style="margin-right:0.5rem">${escHtml(a.id)}</span>${escHtml(a.title)}</span>
              <span class="accordion-arrow">&#9654;</span>
            </div>
            <div class="accordion-body">
              <div class="card-desc" style="margin-bottom:0.75rem">${escHtml(a.description || '')}</div>
              ${(a.questions || []).map(q => `
                <div style="margin-bottom:0.75rem">
                  <div style="font-weight:600;font-size:0.8125rem;margin-bottom:0.35rem"><code style="color:var(--accent2);margin-right:0.35rem">${escHtml(q.id)}</code>${escHtml(q.title)}</div>
                  ${(q.practices || []).length ? `<ul style="font-size:0.8rem;padding-left:1.25rem;color:var(--text-muted)">${q.practices.map(p => `<li style="margin-bottom:0.2rem">${escHtml(p)}</li>`).join('')}</ul>` : ''}
                </div>`).join('')}
            </div>
          </div>`).join('')}
      ` : ''}
    `;
  } catch(e) { /* no well-architected file for this CSP */ }

  setMain(`
    <button class="back-link" onclick="navigate('csp')">&#8592; Cloud Providers</button>
    <div class="page-title">${escHtml(info.name || cspId.toUpperCase())}</div>
    <div class="page-sub">${escHtml(info.description || '')}</div>

    ${benchmarkBtn}

    <h2>Security Services (${svcList.length})</h2>
    <div class="tabs" id="csp-tabs">
      <button class="tab-btn active" onclick="filterCSPSvc('all')">All (${svcList.length})</button>
      ${categories.map(c => `<button class="tab-btn" onclick="filterCSPSvc('${escHtml(c)}')">${escHtml(c)} (${svcList.filter(s=>s.category===c).length})</button>`).join('')}
    </div>

    <div id="csp-svc-list">
      ${svcList.map(s => `
        <div class="card csp-svc-card" data-category="${escHtml(s.category || '')}">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
            <span class="card-title" style="margin:0">${escHtml(s.name)}</span>
            <span class="badge badge-medium">${escHtml(s.category || '')}</span>
            ${s.tier ? `<span class="badge badge-${s.tier === 'free' ? 'low' : 'high'}">${escHtml(s.tier)}</span>` : ''}
          </div>
          <div class="card-desc">${escHtml(s.description || '')}</div>
          ${s.ccmMapping ? `<div style="margin-top:0.5rem">${ccmBadge(Array.isArray(s.ccmMapping) ? s.ccmMapping : [s.ccmMapping])}</div>` : ''}
        </div>`).join('')}
    </div>

    ${wellArchSection}
  `);
}

window.filterCSPSvc = function(cat) {
  document.querySelectorAll('#csp-tabs .tab-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.csp-svc-card').forEach(c => {
    c.style.display = (cat === 'all' || c.dataset.category === cat) ? '' : 'none';
  });
};

async function renderCSPBenchmark(cspId) {
  const data = await load(`standards/csp/${cspId}/cis-benchmark.json`);
  const sections = data.sections || [];

  setMain(`
    <button class="back-link" onclick="navigate('csp','${cspId}')">&#8592; ${escHtml(cspId.toUpperCase())}</button>
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
              <td><span class="badge badge-${c.level === 1 ? 'medium' : 'high'}">L${c.level}</span></td>
              <td>${c.automated ? '<span class="text-success">Yes</span>' : '<span class="text-muted">Manual</span>'}</td>
            </tr>`).join('')}
        </tbody>
      </table></div>
    `).join('')}
  `);
}

// ─── REQUIREMENTS ────────────────────────────────────────────────────────────
async function renderRequirements(sub) {
  if (sub) return renderRequirementDomain(sub);

  const data = await load('requirements/index.json');
  const domains = data.domains || [];

  setMain(`
    <div class="page-title">Security Requirements</div>
    <div class="page-sub">${domains.length} security domains with cloud-specific requirements</div>

    ${domains.map(d => `
      <div class="card card-link" onclick="navigate('requirements','${d.id}')">
        <div style="display:flex;align-items:center;gap:0.75rem">
          <span class="card-title" style="margin:0">${escHtml(d.name)}</span>
          <span class="badge badge-medium">${d.requirementCount || '?'} reqs</span>
        </div>
        <div class="card-desc">${escHtml(d.description || '')}</div>
        ${d.ccmDomains ? `<div style="margin-top:0.5rem">${ccmBadge(d.ccmDomains)}</div>` : ''}
      </div>`).join('')}
  `);
}

async function renderRequirementDomain(domainId) {
  const data = await load(`requirements/by-domain/${domainId}.json`);
  const reqs = data.requirements || [];
  const domain = data.domain || {};

  setMain(`
    <button class="back-link" onclick="navigate('requirements')">&#8592; Requirements</button>
    <div class="page-title">${escHtml(domain.name || domainId)}</div>
    <div class="page-sub">${escHtml(domain.description || '')}</div>
    ${domain.nacsa ? `<div style="margin-bottom:1rem">${nacsaBadge(domain.nacsa)}</div>` : ''}

    ${reqs.map(r => `
      <div class="card">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <code style="font-size:0.75rem;color:var(--accent2)">${escHtml(r.id)}</code>
          <span class="card-title" style="margin:0">${escHtml(r.title)}</span>
          ${priorityBadge(r.priority)}
        </div>
        <div class="card-desc">${escHtml(r.description || '')}</div>
        ${r.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(r.ccmControls)}</div>` : ''}
        ${r.cspGuidance ? `
          <div style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);font-size:0.75rem">
            ${r.cspGuidance.aws ? `<div style="margin-bottom:0.25rem">${cspBadge('AWS')} ${escHtml(r.cspGuidance.aws)}</div>` : ''}
            ${r.cspGuidance.azure ? `<div style="margin-bottom:0.25rem">${cspBadge('Azure')} ${escHtml(r.cspGuidance.azure)}</div>` : ''}
            ${r.cspGuidance.gcp ? `<div>${cspBadge('GCP')} ${escHtml(r.cspGuidance.gcp)}</div>` : ''}
          </div>` : ''}
      </div>`).join('')}
  `);
}

// ─── CONTROLS ────────────────────────────────────────────────────────────────
async function renderControls(sub) {
  if (sub) return renderControlDetail(sub);

  const [domains, controls] = await Promise.all([
    load('controls/domains.json'),
    load('controls/library.json'),
  ]);

  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);
  const allDomains = Array.isArray(domains) ? domains : (domains.domains || []);

  // Discover all CSPs present in cspImplementation across controls
  const cspSet = new Set();
  allControls.forEach(c => {
    if (c.cspImplementation) Object.keys(c.cspImplementation).forEach(k => cspSet.add(k));
  });
  const cspList = [...cspSet].sort();
  const cspLabels = { aws: 'AWS', azure: 'Azure', gcp: 'GCP', alibaba: 'Alibaba', huawei: 'Huawei', oracle: 'Oracle' };

  setMain(`
    <div class="page-title">Control Library</div>
    <div class="page-sub">${allControls.length} controls across ${allDomains.length} domains</div>

    <div class="tabs" id="csp-filter-tabs" style="margin-bottom:1rem">
      <button class="tab-btn active" onclick="filterControlsCSP('all')">All</button>
      ${cspList.map(c => `<button class="tab-btn" onclick="filterControlsCSP('${c}')">${escHtml(cspLabels[c] || c.toUpperCase())}</button>`).join('')}
    </div>

    ${allDomains.map(d => {
      const domControls = allControls.filter(c => c.domain === d.id);
      return `
        <h2>${escHtml(d.name)} (${domControls.length})</h2>
        ${domControls.map(c => {
          const impl = c.cspImplementation || {};
          const cspKeys = Object.keys(impl);
          return `
          <div class="card card-link control-card" onclick="navigate('controls','${c.slug || c.id}')" data-csps="${escHtml(cspKeys.join(','))}">
            <div style="display:flex;align-items:center;gap:0.75rem">
              ${typeBadge(c.type)}
              <span class="card-title" style="margin:0">${escHtml(c.name)}</span>
            </div>
            <div class="card-desc">${escHtml(c.description || '')}</div>
            ${c.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(c.ccmControls)}</div>` : ''}
            <div class="csp-impl-section" style="margin-top:0.75rem;padding-top:0.5rem;border-top:1px solid var(--border);display:none">
              ${cspKeys.map(k => `<div class="csp-impl-item" data-csp="${escHtml(k)}" style="margin-bottom:0.35rem;font-size:0.8rem">${cspBadge(cspLabels[k] || k.toUpperCase())} <span style="color:var(--text-muted)">${escHtml(impl[k])}</span></div>`).join('')}
            </div>
          </div>`;
        }).join('')}
      `;
    }).join('')}
  `);
}

window.filterControlsCSP = function(csp) {
  document.querySelectorAll('#csp-filter-tabs .tab-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.control-card').forEach(card => {
    const csps = (card.dataset.csps || '').split(',').filter(Boolean);
    const implSection = card.querySelector('.csp-impl-section');
    const implItems = card.querySelectorAll('.csp-impl-item');

    if (csp === 'all') {
      // Show all controls, hide CSP implementation details
      card.style.display = '';
      if (implSection) implSection.style.display = 'none';
    } else {
      // Show only controls that have this CSP implementation
      if (csps.includes(csp)) {
        card.style.display = '';
        if (implSection) implSection.style.display = 'block';
        // Show only the selected CSP's implementation
        implItems.forEach(item => {
          item.style.display = item.dataset.csp === csp ? '' : 'none';
        });
      } else {
        card.style.display = 'none';
      }
    }
  });
};

async function renderControlDetail(slug) {
  const [controls, artifactData, evidenceData] = await Promise.all([
    load('controls/library.json'),
    load('artifacts/inventory.json'),
    load('evidence/index.json'),
  ]);
  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);
  const ctrl = allControls.find(c => c.slug === slug || c.id === slug);
  if (!ctrl) { setMain('<div class="empty-state"><div class="empty-state-text">Control not found.</div></div>'); return; }

  // Audit Package: find related artifacts by controlSlugs
  const allArtifacts = Array.isArray(artifactData) ? artifactData : (artifactData.artifacts || []);
  const relatedArtifacts = allArtifacts.filter(a => (a.controlSlugs || []).includes(ctrl.slug || slug));

  // Audit Package: find related evidence by domain match
  const evidenceDomains = evidenceData.evidenceByDomain || evidenceData.domains || [];
  const domainEvidence = evidenceDomains.find(d => d.domainId === ctrl.domain || d.id === ctrl.domain);
  const relatedEvidence = domainEvidence ? (domainEvidence.items || []) : [];

  setMain(`
    <button class="back-link" onclick="navigate('controls')">&#8592; Controls</button>
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
      ${typeBadge(ctrl.type)}
      <div class="page-title" style="margin:0">${escHtml(ctrl.name)}</div>
    </div>
    <div class="page-sub">${escHtml(ctrl.description || '')}</div>

    ${ctrl.ccmControls ? `<div style="margin-bottom:1rem">${ccmBadge(ctrl.ccmControls)}</div>` : ''}
    ${ctrl.nacsa ? `<div style="margin-bottom:1rem">${nacsaBadge(ctrl.nacsa)}</div>` : ''}
    ${ctrl.nistCsf ? `<div style="margin-bottom:1rem">${tagList(ctrl.nistCsf)}</div>` : ''}
    ${ctrl.mitreAttackCloud ? `<div style="margin-bottom:1rem">${ctrl.mitreAttackCloud.map(t => `<span class="badge badge-critical">${escHtml(t)}</span>`).join(' ')}</div>` : ''}

    ${ctrl.maturityLevels ? `
      <h2>Maturity Levels</h2>
      ${Object.entries(ctrl.maturityLevels).map(([lvl, desc]) => `
        <div class="card">
          <div class="card-title">Level ${escHtml(lvl)}</div>
          <div class="card-desc">${escHtml(desc)}</div>
        </div>`).join('')}
    ` : ''}

    ${ctrl.cspImplementation ? `
      <h2>CSP Implementation</h2>
      ${ctrl.cspImplementation.aws ? `<div class="card csp-card aws"><div class="card-title">${cspBadge('AWS')}</div><div class="card-desc">${escHtml(ctrl.cspImplementation.aws)}</div></div>` : ''}
      ${ctrl.cspImplementation.azure ? `<div class="card csp-card azure"><div class="card-title">${cspBadge('Azure')}</div><div class="card-desc">${escHtml(ctrl.cspImplementation.azure)}</div></div>` : ''}
      ${ctrl.cspImplementation.gcp ? `<div class="card csp-card gcp"><div class="card-title">${cspBadge('GCP')}</div><div class="card-desc">${escHtml(ctrl.cspImplementation.gcp)}</div></div>` : ''}
    ` : ''}

    ${(relatedArtifacts.length || relatedEvidence.length) ? `
      <h2>Audit Package</h2>
      ${relatedArtifacts.length ? `
        <h3>Related Artifacts (${relatedArtifacts.length})</h3>
        ${relatedArtifacts.map(a => `
          <div class="artifact-link-card">
            <div class="artifact-link-header">
              <span class="artifact-link-name">${escHtml(a.name)}</span>
              ${a.format ? `<span class="badge badge-medium">${escHtml(a.format)}</span>` : ''}
            </div>
            <div class="artifact-link-meta">${escHtml(a.domain || '')} · ${escHtml(a.frequency || '')} · ${escHtml(a.owner || '')}</div>
            <div class="artifact-link-desc">${escHtml(a.description || '')}</div>
            ${a.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(a.ccmControls)}</div>` : ''}
          </div>`).join('')}
      ` : ''}
      ${relatedEvidence.length ? `
        <h3>Related Evidence (${relatedEvidence.length})</h3>
        ${relatedEvidence.map(e => `
          <div class="artifact-link-card">
            <div class="artifact-link-header">
              <span class="artifact-link-name">${escHtml(e.name)}</span>
              ${e.id ? `<code style="font-size:0.7rem;color:var(--accent2)">${escHtml(e.id)}</code>` : ''}
            </div>
            <div class="artifact-link-desc">${escHtml(e.description || '')}</div>
            ${e.howToVerify ? `<div style="margin-top:0.35rem;font-size:0.8rem;color:var(--text-muted)"><strong>How to verify:</strong> ${escHtml(e.howToVerify)}</div>` : ''}
          </div>`).join('')}
      ` : ''}
    ` : ''}
  `);
}

// ─── EVIDENCE ────────────────────────────────────────────────────────────────
async function renderEvidence(sub) {
  const data = await load('evidence/index.json');
  const domains = data.evidenceByDomain || data.domains || data || [];

  setMain(`
    <div class="page-title">Audit Evidence</div>
    <div class="page-sub">What auditors look for in cloud security assessments</div>

    ${(Array.isArray(domains) ? domains : []).map(d => `
      <h2>${escHtml(d.domainName || d.domainId)}</h2>
      ${(d.items || []).map(item => `
        <div class="card">
          <div class="card-title">${escHtml(item.name)}</div>
          <div class="card-desc">${escHtml(item.description || '')}</div>
          ${item.howToVerify ? `<div style="margin-top:0.5rem;font-size:0.8rem"><strong>How to verify:</strong> ${escHtml(item.howToVerify)}</div>` : ''}
          ${item.whatGoodLooksLike ? `
            <div style="margin-top:0.5rem">
              <div style="font-size:0.7rem;text-transform:uppercase;color:var(--success);margin-bottom:0.25rem">What Good Looks Like</div>
              <ul style="font-size:0.8rem;padding-left:1.25rem">${item.whatGoodLooksLike.map(w => `<li style="color:var(--success)">${escHtml(w)}</li>`).join('')}</ul>
            </div>` : ''}
          ${item.commonGaps ? `
            <div style="margin-top:0.5rem">
              <div style="font-size:0.7rem;text-transform:uppercase;color:var(--danger);margin-bottom:0.25rem">Common Gaps</div>
              <ul style="font-size:0.8rem;padding-left:1.25rem">${item.commonGaps.map(g => `<li style="color:var(--danger)">${escHtml(g)}</li>`).join('')}</ul>
            </div>` : ''}
        </div>`).join('')}
    `).join('')}
  `);
}

// ─── ARTIFACTS ───────────────────────────────────────────────────────────────
async function renderArtifacts(sub) {
  const data = await load('artifacts/inventory.json');
  const artifacts = data.artifacts || data || [];

  setMain(`
    <div class="page-title">Security Artifacts</div>
    <div class="page-sub">${(Array.isArray(artifacts) ? artifacts : []).length} cloud security artifacts and templates</div>

    ${(Array.isArray(artifacts) ? artifacts : []).map(a => `
      <div class="artifact-link-card">
        <div class="artifact-link-header">
          <span class="artifact-link-name">${escHtml(a.name)}</span>
          ${a.format ? `<span class="badge badge-medium">${escHtml(a.format)}</span>` : ''}
        </div>
        <div class="artifact-link-meta">${escHtml(a.domain || '')} · ${escHtml(a.frequency || '')} · ${escHtml(a.owner || '')}</div>
        <div class="artifact-link-desc">${escHtml(a.description || '')}</div>
        ${a.ccmControls ? `<div style="margin-top:0.5rem">${ccmBadge(a.ccmControls)}</div>` : ''}
      </div>`).join('')}
  `);
}

// ─── THREATS ─────────────────────────────────────────────────────────────────
async function renderThreats(sub) {
  if (sub === 'incidents') return renderIncidents();
  if (sub === 'actors') return renderActors();

  setMain(`
    <div class="page-title">Cloud Threat Landscape</div>
    <div class="page-sub">Known incidents and threat actors targeting cloud environments</div>

    <div class="card card-link" onclick="navigate('threats','incidents')">
      <div class="card-title">Known Cloud Incidents</div>
      <div class="card-desc">Major cloud security breaches and their lessons</div>
    </div>
    <div class="card card-link" onclick="navigate('threats','actors')">
      <div class="card-title">Threat Actors</div>
      <div class="card-desc">Groups actively targeting cloud infrastructure</div>
    </div>
  `);
}

async function renderIncidents() {
  const data = await load('threats/known-incidents.json');
  const incidents = data.incidents || [];

  setMain(`
    <button class="back-link" onclick="navigate('threats')">&#8592; Threats</button>
    <div class="page-title">Known Cloud Incidents</div>
    <div class="page-sub">${incidents.length} major cloud security incidents</div>

    ${incidents.map(i => `
      <div class="card incident-card">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span class="card-title" style="margin:0;color:var(--danger)">${escHtml(i.name)}</span>
          <span class="badge badge-critical">${escHtml(i.year)}</span>
          ${i.csp ? cspBadge(i.csp) : ''}
        </div>
        <div class="card-desc"><strong>Impact:</strong> ${escHtml(i.impact || '')}</div>
        <div class="card-desc"><strong>Root Cause:</strong> ${escHtml(i.rootCause || '')}</div>
        <div class="card-desc"><strong>Key Lesson:</strong> ${escHtml(i.keyLesson || '')}</div>
        ${i.killChain ? `
          <div style="margin-top:0.75rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.35rem">Attack Chain</div>
            <div class="attack-chain">
              ${i.killChain.map((s,idx) => `<div class="attack-step"><strong>Step ${idx+1}:</strong> ${escHtml(typeof s === 'string' ? s : s.action || s.description || JSON.stringify(s))}</div>`).join('')}
            </div>
          </div>` : ''}
        ${i.preventiveControls ? `<div style="margin-top:0.5rem">${ccmBadge(i.preventiveControls)}</div>` : ''}
      </div>`).join('')}
  `);
}

async function renderActors() {
  const data = await load('threats/threat-actors.json');
  const actors = data.threatActors || [];

  setMain(`
    <button class="back-link" onclick="navigate('threats')">&#8592; Threats</button>
    <div class="page-title">Cloud Threat Actors</div>
    <div class="page-sub">${actors.length} groups targeting cloud infrastructure</div>

    ${actors.map(a => `
      <div class="card" style="border-left:3px solid var(--danger)">
        <div class="card-title">${escHtml(a.name)}</div>
        ${a.aliases ? `<div class="card-sub">Also: ${escHtml(safeJoin(a.aliases))}</div>` : ''}
        <div class="card-desc"><strong>Motivation:</strong> ${escHtml(a.motivation || '')}</div>
        ${a.targetedCSPs ? `<div style="margin-top:0.5rem">${(Array.isArray(a.targetedCSPs) ? a.targetedCSPs : []).map(c => cspBadge(c)).join(' ')}</div>` : ''}
        ${a.typicalTTPs ? `
          <div style="margin-top:0.5rem">
            <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.25rem">Typical TTPs</div>
            ${tagList(a.typicalTTPs)}
          </div>` : ''}
        ${a.mitreTechniques ? `<div style="margin-top:0.5rem">${a.mitreTechniques.map(t => `<span class="badge badge-critical">${escHtml(t)}</span>`).join(' ')}</div>` : ''}
      </div>`).join('')}
  `);
}

// ─── SECTORS ─────────────────────────────────────────────────────────────────
async function renderSectors(sub) {
  if (sub) return renderSectorDetail(sub);

  const data = await load('sectors/index.json');
  const sectors = data.sectors || [];

  setMain(`
    <div class="page-title">Sectors</div>
    <div class="page-sub">Sector-specific cloud security requirements and regulatory obligations</div>

    ${sectors.map(s => `
      <div class="card card-link" onclick="navigate('sectors','${s.id}')">
        <div style="display:flex;align-items:center;gap:0.75rem">
          <span class="card-title" style="margin:0">${escHtml(s.name)}</span>
          <span class="badge badge-${s.cloudAdoption === 'high' ? 'critical' : s.cloudAdoption === 'medium' ? 'high' : 'medium'}">${escHtml(s.cloudAdoption || '')} adoption</span>
        </div>
        <div class="card-desc">${escHtml(s.description || '')}</div>
        ${s.regulatoryOverlap ? `<div style="margin-top:0.5rem">${tagList(s.regulatoryOverlap)}</div>` : ''}
      </div>`).join('')}
  `);
}

async function renderSectorDetail(sectorId) {
  let data;
  try { data = await load(`sectors/requirements/${sectorId}.json`); }
  catch(e) {
    setMain(`<button class="back-link" onclick="navigate('sectors')">&#8592; Sectors</button>
      <div class="empty-state"><div class="empty-state-text">Sector detail not yet available for ${escHtml(sectorId)}.</div></div>`);
    return;
  }

  const sector = data.sector || data;
  const reqs = data.keyRequirements || data.requirements || [];

  setMain(`
    <button class="back-link" onclick="navigate('sectors')">&#8592; Sectors</button>
    <div class="page-title">${escHtml(data.sectorName || sector.name || sectorId)}</div>
    <div class="page-sub">${escHtml(sector.description || '')}</div>

    ${data.rmitSections ? `
      <h2>BNM RMiT Sections</h2>
      ${data.rmitSections.map(s => `
        <div class="card">
          <div class="card-title">${escHtml(s.id || '')} — ${escHtml(s.title || '')}</div>
          <div class="card-desc">${escHtml(s.description || '')}</div>
          ${s.cloudImplication ? `<div style="margin-top:0.5rem;font-size:0.8rem;color:var(--accent)"><strong>Cloud implication:</strong> ${escHtml(s.cloudImplication)}</div>` : ''}
        </div>`).join('')}
    ` : ''}

    <h2>Key Requirements</h2>
    ${reqs.map(r => `
      <div class="card">
        <div class="card-title">${escHtml(r.title || r.name || '')}</div>
        <div class="card-desc">${escHtml(r.description || '')}</div>
      </div>`).join('')}
  `);
}

// ─── RISK MANAGEMENT ─────────────────────────────────────────────────────────
async function renderRiskManagement(sub) {
  if (sub === 'register') return renderRiskRegister();
  if (sub === 'methodology') return renderRiskMethodology();
  if (sub === 'checklist') return renderRiskChecklist();

  setMain(`
    <div class="page-title">Risk Management</div>
    <div class="page-sub">Cloud-specific risk assessment and treatment</div>

    <div class="card card-link" onclick="navigate('risk-management','methodology')">
      <div class="card-title">Risk Assessment Methodology</div>
      <div class="card-desc">Cloud risk methodology aligned with ISO 27005 and NIST RMF</div>
    </div>
    <div class="card card-link" onclick="navigate('risk-management','register')">
      <div class="card-title">Risk Register</div>
      <div class="card-desc">Cloud-specific risks with ratings and treatment options</div>
    </div>
    <div class="card card-link" onclick="navigate('risk-management','checklist')">
      <div class="card-title">Assessment Checklist</div>
      <div class="card-desc">Cloud security assessment checklist by category</div>
    </div>
  `);
}

async function renderRiskRegister() {
  const data = await load('risk-management/risk-register.json');
  const risks = data.risks || [];
  const categories = [...new Set(risks.map(r => r.category))].filter(Boolean);

  setMain(`
    <button class="back-link" onclick="navigate('risk-management')">&#8592; Risk Management</button>
    <div class="page-title">Cloud Risk Register</div>
    <div class="page-sub">${risks.length} cloud-specific risks</div>

    <div class="tabs" id="risk-tabs">
      <button class="tab-btn active" onclick="filterRisks('all')">All (${risks.length})</button>
      ${categories.map(c => `<button class="tab-btn" onclick="filterRisks('${escHtml(c)}')">${escHtml(c)} (${risks.filter(r=>r.category===c).length})</button>`).join('')}
    </div>

    <div id="risk-list">
      ${risks.map(r => {
        const rating = (r.likelihood || 1) * (r.impact || 1);
        const ratingClass = rating >= 15 ? 'critical' : rating >= 10 ? 'high' : rating >= 5 ? 'medium' : 'low';
        return `
          <div class="card risk-card" data-category="${escHtml(r.category || '')}">
            <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
              <span class="badge badge-${ratingClass}">Risk: ${rating}</span>
              <span class="card-title" style="margin:0">${escHtml(r.title)}</span>
            </div>
            <div class="card-desc">${escHtml(r.description || '')}</div>
            <div style="margin-top:0.5rem;font-size:0.75rem;color:var(--text-muted)">
              L:${r.likelihood} x I:${r.impact} · Treatment: <strong>${escHtml(r.treatmentOption || '')}</strong>
            </div>
            ${r.existingControls ? `<div style="margin-top:0.5rem">${tagList(r.existingControls)}</div>` : ''}
          </div>`;
      }).join('')}
    </div>
  `);
}

window.filterRisks = function(cat) {
  document.querySelectorAll('#risk-tabs .tab-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.risk-card').forEach(c => {
    c.style.display = (cat === 'all' || c.dataset.category === cat) ? '' : 'none';
  });
};

async function renderRiskMethodology() {
  const data = await load('risk-management/methodology.json');

  setMain(`
    <button class="back-link" onclick="navigate('risk-management')">&#8592; Risk Management</button>
    <div class="page-title">${escHtml(data.title || 'Risk Assessment Methodology')}</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${data.phases ? `
      <h2>Assessment Phases</h2>
      <div class="attack-chain">
        ${data.phases.map((p, i) => `<div class="attack-step"><strong>Phase ${i+1}:</strong> ${escHtml(typeof p === 'string' ? p : p.name || p.title || JSON.stringify(p))}</div>`).join('')}
      </div>` : ''}

    ${data.cloudSpecificFactors ? `
      <h2>Cloud-Specific Risk Factors</h2>
      ${tagList(Array.isArray(data.cloudSpecificFactors) ? data.cloudSpecificFactors : [data.cloudSpecificFactors])}` : ''}
  `);
}

async function renderRiskChecklist() {
  const data = await load('risk-management/checklist.json');
  const sections = data.sections || [];

  setMain(`
    <button class="back-link" onclick="navigate('risk-management')">&#8592; Risk Management</button>
    <div class="page-title">Cloud Security Assessment Checklist</div>
    <div class="page-sub">${sections.reduce((n,s) => n + (s.items || s.checks || []).length, 0)} checks across ${sections.length} categories</div>

    ${sections.map(s => `
      <div class="card">
        <div class="card-title">${escHtml(s.name || s.section || '')}</div>
        <ul style="font-size:0.8rem;padding-left:1.25rem;margin-top:0.5rem">
          ${(s.checks || s.items || []).map(c => `<li style="margin-bottom:0.25rem">${escHtml(typeof c === 'string' ? c : c.item || c.check || c.title || JSON.stringify(c))}</li>`).join('')}
        </ul>
      </div>`).join('')}
  `);
}

// ─── FRAMEWORK ───────────────────────────────────────────────────────────────
async function renderFramework(sub) {
  const [domains, controls] = await Promise.all([
    load('standards/csa-ccm/control-domains.json'),
    load('controls/library.json'),
  ]);

  const ccmDomains = Array.isArray(domains) ? domains : (domains.controlDomains || []);
  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);

  setMain(`
    <div class="page-title">Framework Mapping</div>
    <div class="page-sub">CCM v4 domains mapped to controls, NACSA, NIST CSF, and MITRE ATT&amp;CK Cloud</div>

    <div class="table-wrap"><table>
      <thead><tr><th>CCM Domain</th><th>Controls</th><th>NACSA</th><th>NIST CSF</th><th>MITRE</th></tr></thead>
      <tbody>
        ${ccmDomains.map(d => {
          const related = allControls.filter(c => (c.ccmControls || []).some(cc => cc.startsWith(d.id)));
          const nacsa = [...new Set(related.flatMap(c => c.nacsa || []))];
          const nist = [...new Set(related.flatMap(c => c.nistCsf || []))].slice(0, 3);
          const mitre = [...new Set(related.flatMap(c => c.mitreAttackCloud || []))].slice(0, 3);
          return `<tr>
            <td><span class="badge badge-ccm">${escHtml(d.id)}</span> ${escHtml(d.name)}</td>
            <td>${related.length}</td>
            <td>${nacsa.length ? nacsa.map(n => `<span class="badge badge-malaysia" style="margin:1px">${escHtml(n)}</span>`).join('') : '<span style="color:var(--text-muted)">-</span>'}</td>
            <td style="font-size:0.75rem">${nist.length ? nist.map(n => `<span class="tag" style="margin:1px">${escHtml(n)}</span>`).join('') : '<span style="color:var(--text-muted)">-</span>'}</td>
            <td style="font-size:0.75rem">${mitre.length ? mitre.map(m => `<span class="badge badge-critical" style="margin:1px;font-size:0.6rem">${escHtml(m)}</span>`).join('') : '<span style="color:var(--text-muted)">-</span>'}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table></div>
  `);
}

// ─── CROSS-REFERENCES ────────────────────────────────────────────────────────
async function renderCrossRef(sub) {
  if (sub === 'nacsa') return renderCrossNacsa();
  if (sub === 'nist-csf') return renderCrossNistCsf();
  if (sub === 'mitre') return renderCrossMitre();
  if (sub === 'csp-mapping') return renderCrossCSP();
  if (sub === 'rmit-nacsa') return renderCrossRmitNacsa();

  setMain(`
    <div class="page-title">Cross-References</div>
    <div class="page-sub">Bidirectional mappings between frameworks</div>

    <div class="card card-link" onclick="navigate('cross-ref','nacsa')">
      <div class="card-title">CCM v4 &#8594; NACSA Act 854</div>
      <div class="card-desc">How CCM control domains align with Malaysian NCII obligations</div>
    </div>
    <div class="card card-link" onclick="navigate('cross-ref','rmit-nacsa')">
      <div class="card-title">BNM RMiT &#8594; NACSA Act 854</div>
      <div class="card-desc">RMiT cloud clauses mapped to NACSA obligations for financial institutions operating NCII</div>
    </div>
    <div class="card card-link" onclick="navigate('cross-ref','nist-csf')">
      <div class="card-title">CCM v4 &#8594; NIST CSF 2.0</div>
      <div class="card-desc">CCM domains mapped to NIST Cybersecurity Framework functions and subcategories</div>
    </div>
    <div class="card card-link" onclick="navigate('cross-ref','mitre')">
      <div class="card-title">MITRE ATT&amp;CK Cloud &#8594; Controls</div>
      <div class="card-desc">Cloud attack techniques mapped to defensive controls</div>
    </div>
    <div class="card card-link" onclick="navigate('cross-ref','csp-mapping')">
      <div class="card-title">CCM v4 &#8594; CSP Services</div>
      <div class="card-desc">CCM domains mapped to AWS, Azure, and GCP native security services</div>
    </div>
  `);
}

async function renderCrossNacsa() {
  const data = await load('cross-references/ccm-to-nacsa.json');
  const mappings = data.mappings || data || [];

  setMain(`
    <button class="back-link" onclick="navigate('cross-ref')">&#8592; Cross-References</button>
    <div class="page-title">CCM v4 &#8594; NACSA Act 854</div>

    ${(Array.isArray(mappings) ? mappings : []).map(m => `
      <div class="card">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span class="badge badge-ccm">${escHtml(m.ccmDomain)}</span>
          <span class="card-title" style="margin:0">${escHtml(m.ccmDomainName || '')}</span>
        </div>
        ${(m.nacsaSections || []).map(s => `
          <div style="padding:0.35rem 0;font-size:0.8rem;border-bottom:1px solid var(--border)">
            <span class="badge badge-malaysia">${escHtml(s.section)}</span> <strong>${escHtml(s.title || '')}</strong>
            <div style="color:var(--text-muted);margin-top:0.15rem">${escHtml(s.alignment || s.description || '')}</div>
          </div>`).join('')}
      </div>`).join('')}
  `);
}

async function renderCrossNistCsf() {
  const data = await load('cross-references/ccm-to-nist-csf.json');
  const mappings = data.mappings || data || [];

  setMain(`
    <button class="back-link" onclick="navigate('cross-ref')">&#8592; Cross-References</button>
    <div class="page-title">CCM v4 &#8594; NIST CSF 2.0</div>

    <div class="table-wrap"><table>
      <thead><tr><th>CCM Domain</th><th>NIST CSF Subcategories</th></tr></thead>
      <tbody>
        ${(Array.isArray(mappings) ? mappings : []).map(m => `
          <tr>
            <td><span class="badge badge-ccm">${escHtml(m.ccmDomain)}</span> ${escHtml(m.ccmDomainName || '')}</td>
            <td>${(m.nistCsfMappings || []).map(n => `<span class="tag" style="margin:1px">${escHtml(n)}</span>`).join('')}</td>
          </tr>`).join('')}
      </tbody>
    </table></div>
  `);
}

async function renderCrossMitre() {
  const data = await load('cross-references/mitre-to-controls.json');
  const mappings = data.mappings || data || [];

  setMain(`
    <button class="back-link" onclick="navigate('cross-ref')">&#8592; Cross-References</button>
    <div class="page-title">MITRE ATT&amp;CK Cloud &#8594; Defensive Controls</div>

    <div class="table-wrap"><table>
      <thead><tr><th>Technique</th><th>CCM Controls</th><th>Detection Methods</th></tr></thead>
      <tbody>
        ${(Array.isArray(mappings) ? mappings : []).map(m => `
          <tr>
            <td><span class="badge badge-critical">${escHtml(m.techniqueId)}</span><br><span style="font-size:0.75rem">${escHtml(m.techniqueName || '')}</span></td>
            <td>${(m.ccmControls || []).map(c => `<span class="badge badge-ccm" style="margin:1px">${escHtml(c)}</span>`).join('')}</td>
            <td style="font-size:0.75rem">${(m.detectionMethods || []).map(d => `<span class="tag" style="margin:1px">${escHtml(d)}</span>`).join('')}</td>
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

  // Merge by CCM domain
  const allDomains = [...new Set(Object.values(data).flatMap(arr => (Array.isArray(arr) ? arr : []).map(m => m.ccmDomain)))];

  setMain(`
    <button class="back-link" onclick="navigate('cross-ref')">&#8592; Cross-References</button>
    <div class="page-title">CCM v4 &#8594; CSP Services</div>

    <div class="table-wrap"><table>
      <thead><tr><th>CCM Domain</th><th>${cspBadge('AWS')}</th><th>${cspBadge('Azure')}</th><th>${cspBadge('GCP')}</th></tr></thead>
      <tbody>
        ${allDomains.map(d => {
          const get = (csp) => {
            const arr = data[csp] || [];
            const entry = (Array.isArray(arr) ? arr : []).find(m => m.ccmDomain === d);
            return entry ? safeJoin(entry.services || entry.awsServices || entry.azureServices || entry.gcpServices || []) : '-';
          };
          return `<tr>
            <td><span class="badge badge-ccm">${escHtml(d)}</span></td>
            <td style="font-size:0.75rem">${escHtml(get('aws'))}</td>
            <td style="font-size:0.75rem">${escHtml(get('azure'))}</td>
            <td style="font-size:0.75rem">${escHtml(get('gcp'))}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table></div>
  `);
}

async function renderCrossRmitNacsa() {
  const data = await load('cross-references/rmit-to-nacsa.json');
  const mappings = data.mappings || [];

  const relationshipBadge = (r) => {
    const cls = { complementary: 'medium', overlapping: 'high', supplementary: 'low' }[r] || 'low';
    return `<span class="badge badge-${cls}">${escHtml(r)}</span>`;
  };

  setMain(`
    <button class="back-link" onclick="navigate('cross-ref')">&#8592; Cross-References</button>
    <div class="page-title">BNM RMiT &#8594; NACSA Act 854</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${data.verificationNote ? `<div class="card" style="border-left:3px solid var(--warning);font-size:0.8rem;color:var(--text-secondary)">${escHtml(data.verificationNote)}</div>` : ''}

    ${mappings.map(m => `
      <div class="card" style="border-left:3px solid var(--accent2)">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
          <span class="badge" style="background:var(--danger);color:#fff">${escHtml(m.rmitClause)}</span>
          <span class="card-title" style="margin:0">${escHtml(m.rmitTitle)}</span>
          ${relationshipBadge(m.relationship)}
        </div>
        <div style="margin-bottom:0.5rem">
          ${(m.nacsaSections || []).map(s => `<span class="badge badge-malaysia">${escHtml(s)}</span>`).join(' ')}
          <span style="font-size:0.8rem;color:var(--text-muted);margin-left:0.5rem">${escHtml(m.nacsaTitle || '')}</span>
        </div>
        <div class="card-desc">${escHtml(m.notes || '')}</div>
      </div>`).join('')}
  `);
}

// ─── SEARCH ──────────────────────────────────────────────────────────────────
async function renderSearch(query) {
  const q = decodeURIComponent(query || '').toLowerCase();
  if (!q) { setMain('<div class="empty-state"><div class="empty-state-text">Enter a search term.</div></div>'); return; }

  const results = [];

  try {
    const controls = await load('controls/library.json');
    (Array.isArray(controls) ? controls : (controls.controls || [])).forEach(c => {
      if ([c.name, c.description, c.slug, c.id].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'Control', title: c.name, desc: c.description || '', action: () => navigate('controls', c.slug || c.id) });
      }
    });
  } catch(e) {}

  try {
    const incidents = await load('threats/known-incidents.json');
    (incidents.incidents || []).forEach(i => {
      if ([i.name, i.impact, i.keyLesson, i.rootCause].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'Incident', title: i.name, desc: i.impact || '', action: () => navigate('threats', 'incidents') });
      }
    });
  } catch(e) {}

  try {
    const actors = await load('threats/threat-actors.json');
    (actors.threatActors || []).forEach(a => {
      if ([a.name, a.motivation, ...(a.aliases||[])].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'Threat Actor', title: a.name, desc: a.motivation || '', action: () => navigate('threats', 'actors') });
      }
    });
  } catch(e) {}

  try {
    const rmit = await load('standards/rmit-cloud/clauses.json');
    (rmit.clauses || []).forEach(c => {
      if ([c.id, c.title, c.summary, c.section, c.subsection].some(f => String(f||'').toLowerCase().includes(q))) {
        results.push({ type: 'RMiT Clause', title: `${c.id} — ${c.title}`, desc: c.summary || '', action: () => navigate('rmit', `clause-${c.id}`) });
      }
    });
  } catch(e) {}

  setMain(`
    <div class="page-title">Search Results</div>
    <div class="page-sub">${results.length} results for "${escHtml(query)}"</div>

    ${results.length ? results.map(r => `
      <div class="card card-link" onclick="(${r.action.toString()})()">
        <div style="display:flex;align-items:center;gap:0.75rem">
          <span class="badge badge-medium">${escHtml(r.type)}</span>
          <span class="card-title" style="margin:0">${escHtml(r.title)}</span>
        </div>
        <div class="card-desc">${escHtml(r.desc)}</div>
      </div>`).join('') : `<div class="empty-state"><div class="empty-state-text">No results for "${escHtml(query)}".</div></div>`}
  `);
}

// ─── RMiT Cloud ─────────────────────────────────────────────────────────────
async function renderRMiT(sub) {
  if (sub === 'clauses') return renderRMiTClauses();
  if (sub === 'ccm-mapping') return renderRMiTCCMMapping();
  if (sub && sub.startsWith('clause-')) return renderRMiTClauseDetail(sub.replace('clause-', ''));

  const rmit = await load('standards/rmit-cloud/index.json');

  setMain(`
    <div class="page-title">BNM RMiT — Cloud Requirements</div>
    <div class="page-sub">${escHtml(rmit.fullTitle || rmit.standard)}</div>

    <div class="card" style="border-left:3px solid var(--accent2)">
      <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.5rem">Jurisdiction &amp; Applicability</div>
      <div class="card-desc">${escHtml(rmit.jurisdiction || '')}</div>
      <div class="card-desc" style="margin-top:0.5rem">${escHtml(rmit.applicability || '')}</div>
    </div>

    <div class="page-sub" style="margin-top:1.5rem">Cloud-Specific Sections</div>
    ${(rmit.cloudSections || []).map(s => `
      <div class="card card-link" onclick="navigate('rmit','clauses')">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
          <span class="badge badge-ccm">${escHtml(s.id)}</span>
          <span class="card-title" style="margin:0">${escHtml(s.name)}</span>
        </div>
        <div class="card-desc">${escHtml(s.description || '')}</div>
        <div class="card-tags">${(s.clauses || []).map(c => `<span class="badge badge-medium">${escHtml(c)}</span>`).join('')}</div>
      </div>`).join('')}

    <div class="page-sub" style="margin-top:1.5rem">Key Principles</div>
    <div class="card">
      <ul style="margin:0;padding-left:1.25rem;list-style:disc">
        ${(rmit.keyPrinciples || []).map(p => `<li style="margin-bottom:0.35rem;color:var(--text-secondary)">${escHtml(p)}</li>`).join('')}
      </ul>
    </div>

    <div class="page-sub" style="margin-top:1.5rem">Cloud-Relevant Sections</div>
    <div class="table-wrap"><table>
      <thead><tr><th>Section</th><th>Name</th><th>Relevance</th></tr></thead>
      <tbody>
        ${(rmit.cloudRelevantSections || []).map(s => `
          <tr>
            <td><span class="badge badge-medium">${escHtml(s.section)}</span></td>
            <td>${escHtml(s.name)}</td>
            <td style="color:var(--text-secondary)">${escHtml(s.relevance)}</td>
          </tr>`).join('')}
      </tbody>
    </table></div>

    <div class="page-sub" style="margin-top:1.5rem">Appendix 10 Domains</div>
    <div class="card">
      <div class="card-tags">${(rmit.appendix10Areas || []).map(a => `<span class="badge badge-low">${escHtml(a)}</span>`).join('')}</div>
    </div>

    <div style="display:flex;gap:1rem;margin-top:1.5rem;flex-wrap:wrap">
      <div class="card card-link" onclick="navigate('rmit','clauses')" style="flex:1;min-width:200px">
        <div class="card-title">Browse Clauses</div>
        <div class="card-desc">Cloud-specific clauses (10.50-10.52, 17.1-17.5) with requirements, evidence, and CSP guidance</div>
      </div>
      <div class="card card-link" onclick="navigate('rmit','ccm-mapping')" style="flex:1;min-width:200px">
        <div class="card-title">CCM v4 Mapping</div>
        <div class="card-desc">How CSA CCM v4 controls satisfy RMiT cloud obligations</div>
      </div>
    </div>

    ${rmit.relatedRepo ? `
      <div class="card" style="margin-top:1rem;border-left:3px solid var(--info)">
        <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Full RMiT Compliance Database</div>
        <div class="card-desc">${escHtml(rmit.relatedRepoDescription || '')}</div>
        <div style="margin-top:0.5rem"><a href="${escHtml(rmit.relatedRepo)}" target="_blank" rel="noopener" style="color:var(--accent)">${escHtml(rmit.relatedRepo)}</a></div>
      </div>` : ''}
  `);
}

async function renderRMiTClauses() {
  const data = await load('standards/rmit-cloud/clauses.json');
  const clauses = data.clauses || [];

  const markerColors = { S: 'var(--danger)', G: 'var(--warning)' };

  setMain(`
    <button class="back-link" onclick="navigate('rmit')">&#8592; RMiT Cloud</button>
    <div class="page-title">RMiT Cloud Clauses</div>
    <div class="page-sub">${clauses.length} cloud-specific clauses from BNM RMiT</div>

    ${data.verificationNote ? `<div class="card" style="border-left:3px solid var(--warning);font-size:0.8rem;color:var(--text-secondary)">${escHtml(data.verificationNote)}</div>` : ''}

    ${clauses.map(c => `
      <div class="card card-link" onclick="navigate('rmit','clause-${escHtml(c.id)}')" style="border-left:3px solid ${markerColors[c.marker] || 'var(--border)'}">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
          <span class="badge" style="background:${markerColors[c.marker] || 'var(--bg-tertiary)'};color:#fff">${escHtml(c.id)}</span>
          <span class="card-title" style="margin:0">${escHtml(c.title)}</span>
          <span class="badge badge-low">${escHtml(c.marker)} — ${escHtml(c.markerMeaning)}</span>
          <span class="badge badge-medium">${escHtml(c.clauseType)}</span>
        </div>
        <div class="card-desc">${escHtml(c.summary)}</div>
        <div class="card-tags" style="margin-top:0.5rem">
          <span class="badge badge-medium">${escHtml(c.section)}</span>
          ${c.subsection ? `<span class="badge badge-low">${escHtml(c.subsection)}</span>` : ''}
        </div>
      </div>`).join('')}
  `);
}

async function renderRMiTClauseDetail(clauseId) {
  const data = await load('standards/rmit-cloud/clauses.json');
  const clause = (data.clauses || []).find(c => c.id === clauseId);
  if (!clause) {
    setMain(`<button class="back-link" onclick="navigate('rmit','clauses')">&#8592; Clauses</button><div class="empty-state"><div class="empty-state-text">Clause not found.</div></div>`);
    return;
  }

  const markerColors = { S: 'var(--danger)', G: 'var(--warning)' };

  let extraSections = '';

  // Risk areas (10.50)
  if (clause.riskAreas) {
    extraSections += `
      <div class="page-sub" style="margin-top:1.5rem">Risk Assessment Areas</div>
      ${clause.riskAreas.map(r => `
        <div class="card" style="border-left:3px solid var(--accent2)">
          <div class="card-title">${escHtml(r.area)}</div>
          <div class="card-desc">${escHtml(r.description)}</div>
          <div class="card-tags" style="margin-top:0.5rem">${(r.ccmControls || []).map(c => `<span class="badge badge-ccm">${escHtml(c)}</span>`).join('')}</div>
        </div>`).join('')}`;
  }

  // Appendix 10 domains (10.51)
  if (clause.appendix10Domains) {
    extraSections += `
      <div class="page-sub" style="margin-top:1.5rem">Appendix 10 Control Domains</div>
      ${clause.appendix10Domains.map(d => `
        <div class="card" style="border-left:3px solid var(--info)">
          <div class="card-title">${escHtml(d.domain)}</div>
          <ul style="margin:0.5rem 0;padding-left:1.25rem;list-style:disc">
            ${(d.keyControls || []).map(k => `<li style="margin-bottom:0.25rem;color:var(--text-secondary)">${escHtml(k)}</li>`).join('')}
          </ul>
          <div class="card-tags">${(d.ccmControls || []).map(c => `<span class="badge badge-ccm">${escHtml(c)}</span>`).join('')}</div>
        </div>`).join('')}`;
  }

  // Requirements list (10.52, 17.5)
  if (clause.requirements) {
    extraSections += `
      <div class="page-sub" style="margin-top:1.5rem">Requirements</div>
      <div class="card">
        <ul style="margin:0;padding-left:1.25rem;list-style:disc">
          ${clause.requirements.map(r => `<li style="margin-bottom:0.35rem;color:var(--text-secondary)">${escHtml(r)}</li>`).join('')}
        </ul>
      </div>`;
  }

  // CSP region options (10.52)
  if (clause.cspRegionOptions) {
    extraSections += `
      <div class="page-sub" style="margin-top:1.5rem">CSP Data Residency Options</div>
      <div class="table-wrap"><table>
        <thead><tr><th>CSP</th><th>Malaysia Region</th><th>Nearest Approved</th><th>Notes</th></tr></thead>
        <tbody>
          ${clause.cspRegionOptions.map(r => `
            <tr>
              <td><strong>${escHtml(r.csp)}</strong></td>
              <td>${escHtml(r.malaysiaRegion)}</td>
              <td>${escHtml(r.nearestApproved)}</td>
              <td style="color:var(--text-secondary)">${escHtml(r.notes)}</td>
            </tr>`).join('')}
        </tbody>
      </table></div>`;
  }

  // Prerequisites (17.1)
  if (clause.prerequisites) {
    extraSections += `
      <div class="page-sub" style="margin-top:1.5rem">Prerequisites</div>
      ${clause.prerequisites.map(p => `
        <div class="card" style="border-left:3px solid var(--accent)">
          <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.35rem">
            <span class="badge badge-medium">Step ${escHtml(p.step)}</span>
          </div>
          <div class="card-desc">${escHtml(p.requirement)}</div>
          <div class="card-tags" style="margin-top:0.5rem">${(p.ccmControls || []).map(c => `<span class="badge badge-ccm">${escHtml(c)}</span>`).join('')}</div>
        </div>`).join('')}`;
  }

  // Preconditions (17.2)
  if (clause.preconditions) {
    extraSections += `
      <div class="page-sub" style="margin-top:1.5rem">Preconditions</div>
      <div class="card">
        <ul style="margin:0;padding-left:1.25rem;list-style:disc">
          ${clause.preconditions.map(p => `<li style="margin-bottom:0.35rem;color:var(--text-secondary)">${escHtml(p)}</li>`).join('')}
        </ul>
      </div>`;
  }

  // CSP guidance
  let cspGuidance = '';
  if (clause.cspGuidance) {
    const cspNames = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' };
    cspGuidance = `
      <div class="page-sub" style="margin-top:1.5rem">CSP Implementation Guidance</div>
      ${Object.entries(clause.cspGuidance).map(([k, v]) => `
        <div class="card" style="border-left:3px solid var(--${k === 'aws' ? 'aws' : k === 'azure' ? 'azure' : 'gcp'}, var(--accent))">
          <div class="card-title">${escHtml(cspNames[k] || k)}</div>
          <div class="card-desc">${escHtml(v)}</div>
        </div>`).join('')}`;
  }

  setMain(`
    <button class="back-link" onclick="navigate('rmit','clauses')">&#8592; All Clauses</button>
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
      <span class="badge" style="background:${markerColors[clause.marker] || 'var(--bg-tertiary)'};color:#fff;font-size:1rem;padding:0.35rem 0.75rem">${escHtml(clause.id)}</span>
      <div class="page-title" style="margin:0">${escHtml(clause.title)}</div>
    </div>
    <div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap">
      <span class="badge badge-low">${escHtml(clause.marker)} — ${escHtml(clause.markerMeaning)}</span>
      <span class="badge badge-medium">${escHtml(clause.clauseType)}</span>
      <span class="badge badge-medium">${escHtml(clause.section)}</span>
    </div>

    <div class="card">
      <div class="card-desc" style="font-size:0.9rem;line-height:1.6">${escHtml(clause.summary)}</div>
    </div>

    ${clause.higherRiskServices ? `<div class="card" style="border-left:3px solid var(--warning)"><div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Higher-Risk Services</div><div class="card-desc">${escHtml(clause.higherRiskServices)}</div></div>` : ''}
    ${clause.keyConsideration ? `<div class="card" style="border-left:3px solid var(--warning)"><div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Key Consideration</div><div class="card-desc">${escHtml(clause.keyConsideration)}</div></div>` : ''}
    ${clause.implication ? `<div class="card" style="border-left:3px solid var(--info)"><div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:0.35rem">Implication</div><div class="card-desc">${escHtml(clause.implication)}</div></div>` : ''}

    ${extraSections}
    ${cspGuidance}

    ${clause.evidence ? `
      <div class="page-sub" style="margin-top:1.5rem">Evidence Requirements</div>
      <div class="card">
        <div class="card-tags">${clause.evidence.map(e => `<span class="badge badge-low">${escHtml(e)}</span>`).join('')}</div>
      </div>` : ''}

    ${clause.ccmControls ? `
      <div class="page-sub" style="margin-top:1.5rem">Mapped CCM Controls</div>
      <div class="card">
        <div class="card-tags">${clause.ccmControls.map(c => `<span class="badge badge-ccm">${escHtml(c)}</span>`).join('')}</div>
      </div>` : ''}
  `);
}

async function renderRMiTCCMMapping() {
  const data = await load('standards/rmit-cloud/ccm-mapping.json');
  const mappings = data.mappings || [];
  const approach = data.complianceApproach || {};

  setMain(`
    <button class="back-link" onclick="navigate('rmit')">&#8592; RMiT Cloud</button>
    <div class="page-title">RMiT to CCM v4 Mapping</div>
    <div class="page-sub">${escHtml(data.description || '')}</div>

    ${mappings.map(m => `
      <div class="card" style="border-left:3px solid var(--accent2)">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap">
          <span class="card-title" style="margin:0">${escHtml(m.rmitArea)}</span>
          ${(m.rmitClauses || []).map(c => `<span class="badge badge-medium">${escHtml(c)}</span>`).join('')}
        </div>
        <div class="card-desc" style="margin-bottom:0.75rem">${escHtml(m.description)}</div>
        <div class="table-wrap"><table>
          <thead><tr><th>CCM Domain</th><th>Controls</th><th>Alignment</th></tr></thead>
          <tbody>
            ${(m.ccmDomains || []).map(d => `
              <tr>
                <td><span class="badge badge-ccm">${escHtml(d.domain)}</span></td>
                <td>${(d.controls || []).map(c => `<span class="badge badge-low">${escHtml(c)}</span>`).join(' ')}</td>
                <td style="color:var(--text-secondary)">${escHtml(d.alignment)}</td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>`).join('')}

    ${approach.title ? `
      <div class="page-sub" style="margin-top:1.5rem">${escHtml(approach.title)}</div>
      <div class="card">
        <ol style="margin:0;padding-left:1.25rem">
          ${(approach.steps || []).map(s => `<li style="margin-bottom:0.5rem;color:var(--text-secondary)">${escHtml(s)}</li>`).join('')}
        </ol>
      </div>` : ''}
  `);
}

// ─── INIT ────────────────────────────────────────────────────────────────────
window.navigate = navigate;

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', () => {
  route();
  const searchInput = document.getElementById('search-input');
  let debounce;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const q = searchInput.value.trim();
      if (q.length >= 2) navigate('search', encodeURIComponent(q));
    }, 400);
  });
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const q = searchInput.value.trim();
      if (q) navigate('search', encodeURIComponent(q));
    }
  });
});

// === Export Functions ===

function exportToPDF() {
  window.print();
}

function exportToCSV() {
  const view = state.route.view;
  let data = [];
  let filename = `export-${view}-${new Date().toISOString().slice(0,10)}.csv`;

  if (view === 'controls') {
    const list = state.controls.library || state.controls;
    data = list.map(c => ({
      ID: c.id || '',
      Name: c.name,
      Domain: c.domain,
      Description: c.description.replace(/\n/g, ' ')
    }));
  } else if (view === 'risk-management') {
    const list = state.riskManagement?.register || [];
    data = list.map(r => ({
      ID: r.id,
      Risk: r.risk,
      Impact: r.impact,
      Likelihood: r.likelihood,
      Level: r.inherentRiskLevel
    }));
  } else {
    alert('CSV export only supported for Controls and Risk Register views.');
    return;
  }

  if (data.length === 0) {
    alert('No data found to export.');
    return;
  }

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
