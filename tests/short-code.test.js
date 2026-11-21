const test = require('node:test');
const assert = require('node:assert/strict');

const { SHORT_CODE_LENGTH, SHORT_CODE_CHARS, generateShortCode } = require('../short-code');

const LOOK_ALIKES = ['0', 'O', 'o', '1', 'l', 'I'];

test('short code alphabet excludes look-alike characters', () => {
  for (const ch of LOOK_ALIKES) {
    assert.ok(!SHORT_CODE_CHARS.includes(ch), `alphabet contains ${ch}`);
  }
  assert.equal(new Set(SHORT_CODE_CHARS).size, SHORT_CODE_CHARS.length, 'alphabet has duplicates');
  assert.equal(SHORT_CODE_CHARS.length, 56);
});

test('generated short codes never contain look-alike characters', () => {
  for (let i = 0; i < 2000; i++) {
    const code = generateShortCode();
    assert.equal(code.length, SHORT_CODE_LENGTH);
    assert.match(code, /^[a-zA-Z0-9]{7}$/, 'must still pass the lookup pattern');
    for (const ch of LOOK_ALIKES) {
      assert.ok(!code.includes(ch), `${code} contains ${ch}`);
    }
  }
});
