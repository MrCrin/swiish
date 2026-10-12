const crypto = require('crypto');

const SHORT_CODE_LENGTH = 7;

// Excludes characters that look alike in most fonts (0 O o 1 l I), so a code read
// off a printed card, a QR caption or a share link can be typed back correctly.
// Lookups still accept any 7-character [a-zA-Z0-9] code, so codes issued before
// this change keep working.
const SHORT_CODE_CHARS = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateShortCode() {
  let code = '';
  const charsLength = SHORT_CODE_CHARS.length;
  const maxValid = Math.floor(256 / charsLength) * charsLength; // 224 for 56 chars

  for (let i = 0; i < SHORT_CODE_LENGTH; i++) {
    let randomByte;
    do {
      randomByte = crypto.randomBytes(1)[0];
    } while (randomByte >= maxValid);

    code += SHORT_CODE_CHARS[randomByte % charsLength];
  }
  return code;
}

module.exports = { SHORT_CODE_LENGTH, SHORT_CODE_CHARS, generateShortCode };
