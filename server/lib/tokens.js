const crypto = require('crypto');
const { SHORT_CODE_LENGTH, SHORT_CODE_CHARS } = require('../config/env');

function generateUuid() {
  return crypto.randomUUID();
}

function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function generateShortCode() {
  let code = '';
  const charsLength = SHORT_CODE_CHARS.length;
  const maxValid = Math.floor(256 / charsLength) * charsLength; // 248 for 62 chars

  for (let i = 0; i < SHORT_CODE_LENGTH; i++) {
    let randomByte;
    do {
      randomByte = crypto.randomBytes(1)[0];
    } while (randomByte >= maxValid);

    code += SHORT_CODE_CHARS[randomByte % charsLength];
  }
  return code;
}

function ensureUniqueShortCode(db, callback) {
  let attempts = 0;
  const tryGenerate = () => {
    const code = generateShortCode();
    db.get("SELECT 1 FROM cards WHERE short_code = ?", [code], (err, row) => {
      if (err) return callback(err);
      if (!row) return callback(null, code);
      attempts++;
      if (attempts > 10) return callback(new Error('Failed to generate unique short code'));
      tryGenerate();
    });
  };
  tryGenerate();
}

module.exports = {
  generateUuid,
  generateSecureToken,
  generateShortCode,
  ensureUniqueShortCode,
};
