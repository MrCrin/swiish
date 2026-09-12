function normalizeMatrixUrl(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return '';

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (error) {
    throw new Error('Invalid Matrix URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Invalid Matrix URL');
  }

  return normalized;
}

module.exports = { normalizeMatrixUrl };
