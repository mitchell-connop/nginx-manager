/**
 * nginx-manager — lib/linediff.js
 *
 * Minimal unified line diff (LCS-based) for previewing config edits.
 * Config files here are a few hundred lines, so O(n·m) is fine.
 */

'use strict';

function unifiedDiff(a, b, context = 3) {
  const A = a === '' ? [] : a.split('\n'), B = b === '' ? [] : b.split('\n');
  const n = A.length, m = B.length;
  // LCS table from the end
  const L = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      L[i][j] = A[i] === B[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    }
  }
  // walk to an edit script: [' '|'-'|'+', text, aLine, bLine]
  const ops = [];
  let i = 0, j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && A[i] === B[j]) { ops.push([' ', A[i], i, j]); i++; j++; }
    else if (i < n && (j === m || L[i + 1][j] >= L[i][j + 1])) { ops.push(['-', A[i], i, j]); i++; }
    else { ops.push(['+', B[j], i, j]); j++; }
  }
  // group into hunks with context
  const changed = ops.map((o, k) => (o[0] !== ' ' ? k : -1)).filter(k => k >= 0);
  if (!changed.length) return '';
  const hunks = [];
  let start = Math.max(0, changed[0] - context), end = Math.min(ops.length, changed[0] + context + 1);
  for (const k of changed.slice(1)) {
    if (k - context <= end) end = Math.min(ops.length, k + context + 1);
    else { hunks.push([start, end]); start = Math.max(0, k - context); end = Math.min(ops.length, k + context + 1); }
  }
  hunks.push([start, end]);

  const out = [];
  for (const [s, e] of hunks) {
    const slice = ops.slice(s, e);
    const aStart = slice[0][2] + 1, bStart = slice[0][3] + 1;
    const aLen = slice.filter(o => o[0] !== '+').length, bLen = slice.filter(o => o[0] !== '-').length;
    out.push(`@@ -${aStart},${aLen} +${bStart},${bLen} @@`);
    for (const [op, text] of slice) out.push(op + text);
  }
  return out.join('\n') + '\n';
}

module.exports = { unifiedDiff };
