const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeMatrixUrl } = require('../matrix-url');

test('normalizes safe Matrix share links for card storage', () => {
  assert.equal(
    normalizeMatrixUrl('  https://matrix.to/#/@alice:example.org  '),
    'https://matrix.to/#/@alice:example.org'
  );
  assert.equal(normalizeMatrixUrl(''), '');
  assert.throws(
    () => normalizeMatrixUrl('javascript:alert(1)'),
    /Invalid Matrix URL/
  );
});
