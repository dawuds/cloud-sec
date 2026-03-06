#!/usr/bin/env node
/* validate.js — Cloud Security Framework data integrity checks
   Run: node validate.js
   Checks JSON parsing, cross-references, risk math, domain consistency,
   CCM IDs, sector files, and duplicate control slugs.
*/

'use strict';

const fs = require('fs');
const path = require('path');

let pass = 0;
let fail = 0;
let warn = 0;

function ok(msg)   { pass++; console.log(`  PASS  ${msg}`); }
function bad(msg)  { fail++; console.log(`  FAIL  ${msg}`); }
function warning(msg) { warn++; console.log(`  WARN  ${msg}`); }

function loadJSON(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

// ─── Check 1: All JSON files parse correctly ──────────────────────────────────
function checkJSONParsing() {
  console.log('\n--- Check 1: JSON Parsing ---');
  const jsonFiles = findJSONFiles('.');
  let parseErrors = 0;

  for (const f of jsonFiles) {
    try {
      JSON.parse(fs.readFileSync(f, 'utf8'));
    } catch (e) {
      bad(`${f}: ${e.message}`);
      parseErrors++;
    }
  }

  if (parseErrors === 0) {
    ok(`All ${jsonFiles.length} JSON files parse correctly`);
  }
}

function findJSONFiles(dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    if (entry.isDirectory()) {
      results.push(...findJSONFiles(full));
    } else if (entry.name.endsWith('.json')) {
      results.push(full);
    }
  }
  return results;
}

// ─── Check 2: All controlSlugs in artifacts resolve to controls ───────────────
function checkControlSlugs() {
  console.log('\n--- Check 2: Artifact controlSlugs resolve to controls ---');

  const controls = loadJSON('controls/library.json');
  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);
  const validSlugs = new Set(allControls.map(c => c.slug).filter(Boolean));

  const artifacts = loadJSON('artifacts/inventory.json');
  const allArtifacts = Array.isArray(artifacts) ? artifacts : (artifacts.artifacts || []);

  let orphanCount = 0;
  for (const artifact of allArtifacts) {
    if (!artifact.controlSlugs) continue;
    for (const slug of artifact.controlSlugs) {
      if (!validSlugs.has(slug)) {
        bad(`Artifact "${artifact.name}" references unknown controlSlug: ${slug}`);
        orphanCount++;
      }
    }
  }

  if (orphanCount === 0) {
    ok(`All controlSlugs in ${allArtifacts.length} artifacts resolve to valid controls`);
  }
}

// ─── Check 3: Domain IDs in requirements/by-domain/ match index.json ──────────
function checkRequirementDomains() {
  console.log('\n--- Check 3: Requirement domain files match index ---');

  const reqIndex = loadJSON('requirements/index.json');
  const indexDomains = new Set((reqIndex.domains || []).map(d => d.id));

  const domainDir = 'requirements/by-domain';
  if (!fs.existsSync(domainDir)) {
    bad('requirements/by-domain/ directory not found');
    return;
  }

  const files = fs.readdirSync(domainDir).filter(f => f.endsWith('.json'));
  let mismatchCount = 0;

  for (const file of files) {
    const domainId = file.replace('.json', '');
    if (!indexDomains.has(domainId)) {
      bad(`Domain file "${file}" has no matching entry in requirements/index.json`);
      mismatchCount++;
    }
  }

  for (const domainId of indexDomains) {
    if (!files.includes(`${domainId}.json`)) {
      bad(`Domain "${domainId}" listed in index but no file at requirements/by-domain/${domainId}.json`);
      mismatchCount++;
    }
  }

  if (mismatchCount === 0) {
    ok(`All ${indexDomains.size} requirement domains match their detail files`);
  }
}

// ─── Check 4: Evidence domain IDs match requirement domains ───────────────────
function checkEvidenceDomains() {
  console.log('\n--- Check 4: Evidence domains match requirement domains ---');

  const reqIndex = loadJSON('requirements/index.json');
  const reqDomains = new Set((reqIndex.domains || []).map(d => d.id));

  const evidence = loadJSON('evidence/index.json');
  const evidenceDomains = evidence.evidenceByDomain || evidence.domains || [];

  let mismatchCount = 0;
  for (const ed of evidenceDomains) {
    const domainId = ed.domainId || ed.id;
    if (domainId && !reqDomains.has(domainId)) {
      bad(`Evidence domain "${domainId}" not found in requirements`);
      mismatchCount++;
    }
  }

  if (mismatchCount === 0) {
    const evidenceIds = evidenceDomains.map(e => e.domainId || e.id).filter(Boolean);
    const missingEvidence = [...reqDomains].filter(d => !evidenceIds.includes(d));
    if (missingEvidence.length > 0) {
      warning(`${missingEvidence.length} requirement domains have no evidence: ${missingEvidence.join(', ')}`);
    } else {
      ok(`All evidence domains match requirement domains`);
    }
  }
}

// ─── Check 5: Risk register math — likelihood x impact ───────────────────────
function checkRiskMath() {
  console.log('\n--- Check 5: Risk register math (likelihood x impact) ---');

  const data = loadJSON('risk-management/risk-register.json');
  const risks = data.risks || [];

  let errorCount = 0;
  for (const risk of risks) {
    const expected = (risk.likelihood || 0) * (risk.impact || 0);
    if (risk.riskScore !== undefined && risk.riskScore !== expected) {
      bad(`Risk "${risk.title}": riskScore=${risk.riskScore} but L(${risk.likelihood}) x I(${risk.impact}) = ${expected}`);
      errorCount++;
    }
    if (!risk.likelihood || !risk.impact) {
      warning(`Risk "${risk.title}": missing likelihood or impact`);
    }
  }

  if (errorCount === 0) {
    ok(`All ${risks.length} risks have correct likelihood x impact math`);
  }
}

// ─── Check 6: CCM domain IDs in control-domains.json match cross-references ──
function checkCCMDomainIDs() {
  console.log('\n--- Check 6: CCM domain IDs consistency ---');

  const ccm = loadJSON('standards/csa-ccm/control-domains.json');
  const ccmDomains = (Array.isArray(ccm) ? ccm : (ccm.controlDomains || [])).map(d => d.id);
  const ccmSet = new Set(ccmDomains);

  // Check cross-reference files reference valid CCM domain IDs
  const crossRefFiles = [
    'cross-references/ccm-to-nacsa.json',
    'cross-references/ccm-to-nist-csf.json',
    'cross-references/ccm-to-aws.json',
    'cross-references/ccm-to-azure.json',
    'cross-references/ccm-to-gcp.json',
  ];

  let errorCount = 0;
  for (const file of crossRefFiles) {
    if (!fs.existsSync(file)) continue;
    try {
      const data = loadJSON(file);
      const mappings = data.mappings || data || [];
      if (!Array.isArray(mappings)) continue;
      for (const m of mappings) {
        const domain = m.ccmDomain;
        if (domain && !ccmSet.has(domain)) {
          bad(`${file}: references unknown CCM domain "${domain}"`);
          errorCount++;
        }
      }
    } catch (e) {
      bad(`${file}: failed to parse — ${e.message}`);
      errorCount++;
    }
  }

  if (errorCount === 0) {
    ok(`CCM domain IDs consistent across control-domains.json and ${crossRefFiles.length} cross-reference files`);
  }
}

// ─── Check 7: Sector IDs in index.json have corresponding detail files ────────
function checkSectorFiles() {
  console.log('\n--- Check 7: Sector detail files ---');

  const sectors = loadJSON('sectors/index.json');
  const sectorList = sectors.sectors || [];

  let missingCount = 0;
  for (const s of sectorList) {
    const detailPath = `sectors/requirements/${s.id}.json`;
    if (!fs.existsSync(detailPath)) {
      bad(`Sector "${s.name}" (${s.id}) has no detail file at ${detailPath}`);
      missingCount++;
    }
  }

  if (missingCount === 0) {
    ok(`All ${sectorList.length} sectors have corresponding detail files`);
  }
}

// ─── Check 8: No duplicate control slugs ──────────────────────────────────────
function checkDuplicateSlugs() {
  console.log('\n--- Check 8: No duplicate control slugs ---');

  const controls = loadJSON('controls/library.json');
  const allControls = Array.isArray(controls) ? controls : (controls.controls || []);

  const slugs = allControls.map(c => c.slug).filter(Boolean);
  const seen = new Set();
  let dupeCount = 0;

  for (const slug of slugs) {
    if (seen.has(slug)) {
      bad(`Duplicate control slug: "${slug}"`);
      dupeCount++;
    }
    seen.add(slug);
  }

  if (dupeCount === 0) {
    ok(`All ${slugs.length} control slugs are unique`);
  }
}

// ─── Run all checks ──────────────────────────────────────────────────────────
console.log('Cloud Security Framework — Data Validation');
console.log('='.repeat(50));

checkJSONParsing();
checkControlSlugs();
checkRequirementDomains();
checkEvidenceDomains();
checkRiskMath();
checkCCMDomainIDs();
checkSectorFiles();
checkDuplicateSlugs();

console.log('\n' + '='.repeat(50));
console.log(`Results: ${pass} passed, ${fail} failed, ${warn} warnings`);
console.log('='.repeat(50));

if (fail > 0) {
  process.exit(1);
}
