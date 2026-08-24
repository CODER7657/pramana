#!/usr/bin/env node
// Recompute a PRAMANA evidence ledger without PRAMANA.
//
//   node tools/verify.mjs var/ledger.jsonl
//
// Zero dependencies and zero imports from this project. 63 lines of code, about
// half of which is the RFC 8785 canonicaliser.
// It exists because "a third party in a dispute can recompute the hash from
// the same facts in a different language" was an assertion, and an assertion
// is not an artifact. This is the artifact. If it disagrees with the Python,
// one of them is wrong and the claim was never true.
//
// The contract it re-implements, from RFC 8785 (JCS) and chain_log.py:
//
//   verdict_hash = sha256(JCS(record.verdict))
//   record_hash  = sha256(JCS({sequence, verdict_hash, prev_hash,
//                              recorded_at, mandate_ref, trace_id, decision}))
//   record[0].prev_hash = 64 zeros;  record[i].prev_hash = record_hash(i-1)
//
// What it does NOT prove: that PRAMANA produced this chain. Recomputation
// shows internal consistency and nothing about provenance -- that needs a
// signature over the head, which is not shipped. See POSTMORTEM.md.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const GENESIS = '0'.repeat(64);

// RFC 8785. JavaScript is the easy direction: JSON.stringify already emits
// ES6 number formatting and the shortest string escapes, which is what JCS
// specifies. What it does not do is order keys, so that is the work here.
// Array.prototype.sort compares by UTF-16 code unit, which is JCS's rule.
function jcs(value) {
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const body = Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`)
      .join(',');
    return `{${body}}`;
  }
  return JSON.stringify(value);
}

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

const linking = (r) => ({
  sequence: r.sequence,
  verdict_hash: r.verdict_hash,
  prev_hash: r.prev_hash,
  recorded_at: r.recorded_at,
  mandate_ref: r.mandate_ref,
  trace_id: r.trace_id,
  decision: r.decision,
});

const path = process.argv[2];
if (!path) {
  console.error('usage: node tools/verify.mjs <ledger.jsonl>');
  process.exit(2);
}

const records = readFileSync(path, 'utf8')
  .split('\n')
  .filter((line) => line.trim())
  .map((line) => JSON.parse(line));

const fail = (seq, why) => {
  console.error(`BROKEN at record ${seq}: ${why}`);
  process.exit(1);
};

let expectedPrev = GENESIS;
for (const [i, r] of records.entries()) {
  if (r.sequence !== i) fail(r.sequence, `out of order: expected sequence ${i}`);
  if (r.prev_hash !== expectedPrev) {
    fail(r.sequence, 'broken link: prev_hash does not match the preceding record');
  }
  // Absence is not compliance here either: a record with no verdict body
  // cannot be recomputed, and that is a failure, not a pass. The Python
  // verifier once treated it as a pass, which is POSTMORTEM defect P0-2.
  if (!r.verdict || typeof r.verdict !== 'object') {
    fail(r.sequence, 'verdict body missing, so its hash cannot be recomputed');
  }
  const verdictHash = sha256(jcs(r.verdict));
  if (verdictHash !== r.verdict_hash) {
    fail(r.sequence, `verdict body does not match its hash\n  stored     ${r.verdict_hash}\n  recomputed ${verdictHash}`);
  }
  const recordHash = sha256(jcs(linking(r)));
  if (r.record_hash && recordHash !== r.record_hash) {
    fail(r.sequence, `record hash does not match\n  stored     ${r.record_hash}\n  recomputed ${recordHash}`);
  }
  expectedPrev = recordHash;
}

console.log(`OK  ${records.length} record(s) verified, chain intact`);
console.log(`    head ${expectedPrev}`);
console.log('    recomputed by node with no PRAMANA code and no dependencies');
for (const r of records) {
  console.log(`    #${r.sequence}  ${r.decision.padEnd(6)}  ${r.verdict_hash.slice(0, 16)}...`);
}
