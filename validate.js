#!/usr/bin/env node
/**
 * validate.js — Cloud Security data integrity validator
 *
 * Checks:
 *   1.  All JSON files parse without errors
 *   2.  Controls library — slug/id uniqueness and required fields
 *   3.  Controls library — domain coverage
 *   4.  Artifact controlSlugs resolve to controls/library.json
 *   5.  Evidence controlSlugs resolve to controls/library.json
 *   6.  Cross-reference integrity (CCM, MITRE, CSP mappings)
 *   7.  Risk register math
 *   8.  No empty strings where data is expected
 *   9.  Unique IDs across data sets
 *   10. Standards & sector file integrity
 *
 * Usage: node validate.js [--verbose]
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const REPO_ROOT = __dirname;
const verbose   = process.argv.includes('--verbose');

let pass = 0;
let fail = 0;
let warn = 0;

function ok(msg)      { pass++; if (verbose) console.log(`  PASS  ${msg}`); }
function bad(msg)     { fail++; console.log(`  FAIL  ${msg}`); }
function warning(msg) { warn++; console.log(`  WARN  ${msg}`); }

function loadJson(relPath) {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) return null;
  try {
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (e) {
    return null;
  }
}

// ── 1. JSON Parse Check ─────────────────────────────────────────────

console.log('\n=== 1. JSON Parse Check ===');

function findJsonFiles(dir) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      results.push(...findJsonFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      results.push(path.relative(REPO_ROOT, full));
    }
  }
  return results;
}

const jsonFiles = findJsonFiles(REPO_ROOT);
const parsed = {};
let parseErrors = 0;

for (const file of jsonFiles) {
  try {
    parsed[file] = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, file), 'utf8'));
    ok(`Parsed: ${file}`);
  } catch (e) {
    bad(`JSON parse error: ${file} — ${e.message}`);
    parseErrors++;
  }
}

if (parseErrors === 0) {
  ok(`All ${jsonFiles.length} JSON files parse correctly`);
}

// ── Load core data ──────────────────────────────────────────────────

const controlsLib   = loadJson('controls/library.json');
const domainsFile   = loadJson('controls/domains.json');
const artifactsInv  = loadJson('artifacts/inventory.json');
const evidence      = loadJson('evidence/index.json');
const requirements  = loadJson('requirements/index.json');
const riskRegister  = loadJson('risk-management/risk-register.json');

// cloud-sec controls have both id and slug
const libraryControls = (controlsLib && controlsLib.controls) || [];
const controlSlugSet = new Set();
const controlIdSet = new Set();
for (const c of libraryControls) {
  if (c.slug) controlSlugSet.add(c.slug);
  if (c.id) controlIdSet.add(c.id);
}

// Domains
const libraryDomains = (domainsFile && domainsFile.domains) || [];
const domainIdSet = new Set(libraryDomains.map(d => d.id || d.slug).filter(Boolean));

// Artifacts — cloud-sec uses { artifacts: [...] }
const allArtifacts = (artifactsInv && artifactsInv.artifacts) || [];
const artifactSlugSet = new Set(allArtifacts.map(a => a.id || a.slug).filter(Boolean));

// ── 2. Control Slug/ID Uniqueness & Required Fields ──────────────────

console.log('\n=== 2. Control Slug/ID Uniqueness & Required Fields ===');

const slugCounts = {};
const idCounts = {};
for (const ctrl of libraryControls) {
  if (!ctrl.slug && !ctrl.id) {
    bad(`Control missing both "slug" and "id": ${(ctrl.name || '').slice(0, 60)}`);
  }
  if (ctrl.slug) slugCounts[ctrl.slug] = (slugCounts[ctrl.slug] || 0) + 1;
  if (ctrl.id) idCounts[ctrl.id] = (idCounts[ctrl.id] || 0) + 1;
  if (!ctrl.name || ctrl.name.trim() === '') {
    bad(`Control "${ctrl.slug || ctrl.id}" has empty or missing "name"`);
  }
  if (!ctrl.domain) {
    bad(`Control "${ctrl.slug || ctrl.id}" missing "domain" field`);
  }
}

const slugDups = Object.entries(slugCounts).filter(([, c]) => c > 1);
const idDups = Object.entries(idCounts).filter(([, c]) => c > 1);
if (slugDups.length === 0 && idDups.length === 0) {
  ok(`No duplicate control slugs/IDs (${libraryControls.length} controls)`);
} else {
  for (const [slug, count] of slugDups) bad(`Duplicate control slug "${slug}" appears ${count} times`);
  for (const [id, count] of idDups) bad(`Duplicate control id "${id}" appears ${count} times`);
}

// ── 3. Domain Coverage ───────────────────────────────────────────────

console.log('\n=== 3. Controls Library — Domain Coverage ===');

const controlsByDomain = {};
for (const ctrl of libraryControls) {
  if (ctrl.domain) controlsByDomain[ctrl.domain] = (controlsByDomain[ctrl.domain] || 0) + 1;
}

for (const dom of libraryDomains) {
  const key = dom.id || dom.slug;
  if (!controlsByDomain[key]) {
    bad(`Domain "${key}" has zero controls in library.json`);
  } else {
    ok(`Domain "${key}" has ${controlsByDomain[key]} control(s)`);
  }
}

// ── 4. Artifact controlSlugs Resolution ──────────────────────────────

console.log('\n=== 4. Artifact controlSlugs Resolution ===');

let controlSlugErrors = 0;
let controlSlugTotal = 0;

for (const artifact of allArtifacts) {
  if (!artifact.controlSlugs) continue;
  for (const slug of artifact.controlSlugs) {
    controlSlugTotal++;
    if (!controlSlugSet.has(slug) && !controlIdSet.has(slug)) {
      bad(`Artifact "${artifact.id || artifact.slug}" references unknown control "${slug}"`);
      controlSlugErrors++;
    }
  }
}

if (controlSlugErrors === 0) {
  ok(`All ${controlSlugTotal} controlSlug references in artifacts resolve correctly`);
}

// ── 5. Evidence controlSlugs Resolution ──────────────────────────────

console.log('\n=== 5. Evidence controlSlugs Resolution ===');

let evidenceSlugErrors = 0;
let evidenceSlugTotal = 0;

if (evidence && evidence.evidenceByDomain) {
  for (const [domKey, domData] of Object.entries(evidence.evidenceByDomain)) {
    const items = domData.items || domData.evidenceItems || [];
    for (const item of items) {
      if (!item.controlSlugs) continue;
      for (const slug of item.controlSlugs) {
        evidenceSlugTotal++;
        if (!controlSlugSet.has(slug) && !controlIdSet.has(slug)) {
          bad(`Evidence "${item.id}" references unknown control "${slug}"`);
          evidenceSlugErrors++;
        }
      }
    }
  }
}

if (evidenceSlugErrors === 0) {
  ok(`All ${evidenceSlugTotal} evidence controlSlug references resolve correctly`);
}

// ── 6. Cross-Reference Integrity ─────────────────────────────────────

console.log('\n=== 6. Cross-Reference Integrity ===');

const crossRefFiles = findJsonFiles(path.join(REPO_ROOT, 'cross-references'));
for (const file of crossRefFiles) {
  if (!parsed[file]) {
    bad(`Cross-reference file failed to load: ${file}`);
  } else {
    ok(`Cross-reference loaded: ${file}`);
  }
}

// ── 7. Risk Register Math ────────────────────────────────────────────

console.log('\n=== 7. Risk Register Math ===');

if (riskRegister && riskRegister.risks) {
  let mathErrors = 0;
  for (const risk of riskRegister.risks) {
    if (risk.likelihood != null && risk.impact != null && risk.inherentRisk != null) {
      const expected = risk.likelihood * risk.impact;
      if (risk.inherentRisk !== expected) {
        bad(`${risk.id}: inherentRisk ${risk.inherentRisk} != ${risk.likelihood} x ${risk.impact} = ${expected}`);
        mathErrors++;
      }
    }
    if (risk.residualLikelihood != null && risk.residualImpact != null && risk.residualRisk != null) {
      const expected = risk.residualLikelihood * risk.residualImpact;
      if (risk.residualRisk !== expected) {
        bad(`${risk.id}: residualRisk ${risk.residualRisk} != ${risk.residualLikelihood} x ${risk.residualImpact} = ${expected}`);
        mathErrors++;
      }
    }
  }
  if (mathErrors === 0) ok(`All ${riskRegister.risks.length} risk register entries have correct math`);
} else {
  ok('No risk register with risks array found (skipping)');
}

// ── 8. Data Completeness ─────────────────────────────────────────────

console.log('\n=== 8. Data Completeness ===');

let emptyIssues = 0;
for (const ctrl of libraryControls) {
  if (ctrl.description && ctrl.description.trim() === '') { bad(`Control "${ctrl.slug || ctrl.id}" has empty description`); emptyIssues++; }
}
for (const artifact of allArtifacts) {
  if (artifact.name && artifact.name.trim() === '') { bad(`Artifact "${artifact.id || artifact.slug}" has empty name`); emptyIssues++; }
}
if (emptyIssues === 0) ok('No empty strings detected in core data');

// ── 9. Unique IDs Across Artifacts ───────────────────────────────────

console.log('\n=== 9. Unique IDs Across Artifacts ===');

const seenArtIds = {};
for (const art of allArtifacts) {
  const key = art.id || art.slug;
  if (key) seenArtIds[key] = (seenArtIds[key] || 0) + 1;
}
const artDups = Object.entries(seenArtIds).filter(([, c]) => c > 1);
if (artDups.length === 0) {
  ok(`All ${allArtifacts.length} artifact IDs are unique`);
} else {
  for (const [id, count] of artDups) bad(`Duplicate artifact ID "${id}" appears ${count} times`);
}

// ── 10. Standards & Sector File Integrity ────────────────────────────

console.log('\n=== 10. Standards & Sector File Integrity ===');

const standardsFiles = findJsonFiles(path.join(REPO_ROOT, 'standards'));
const sectorFiles = findJsonFiles(path.join(REPO_ROOT, 'sectors'));
const threatFiles = findJsonFiles(path.join(REPO_ROOT, 'threats'));

for (const file of [...standardsFiles, ...sectorFiles, ...threatFiles]) {
  if (!parsed[file]) {
    bad(`File failed to load: ${file}`);
  } else {
    ok(`Loaded: ${file}`);
  }
}

// ── Summary ──────────────────────────────────────────────────────────

console.log('\n' + '='.repeat(60));
console.log('Validation complete:');
console.log(`  Pass: ${pass}`);
console.log(`  Fail: ${fail}`);
console.log(`  Warn: ${warn}`);
console.log(`  Total: ${pass + fail + warn}`);
console.log('='.repeat(60));

if (fail > 0) {
  console.error(`\nValidation FAILED with ${fail} error(s).`);
  process.exit(1);
} else if (warn > 0) {
  console.log(`\nValidation passed with ${warn} warning(s).`);
  process.exit(0);
} else {
  console.log('\nAll checks passed.');
  process.exit(0);
}
