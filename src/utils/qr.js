import { sanitizeText } from './sanitize';

// --- QR PAYLOAD STORAGE KEYS ---
const QR_STORAGE_KEY = 'swiish:lastQrPayload';

// Build a vCard string for QR code encoding (simplified for reliable scanning)
// When scanned, this will add the contact directly to the phone
const buildQrPayload = (shortCode, data) => {
  const { personal = {}, contact = {} } = data || {};

  const safe = (v, maxLen = 120) => sanitizeText(v || '').substring(0, maxLen);

  const firstName = safe(personal.firstName || '', 40);
  const lastName = safe(personal.lastName || '', 40);
  const fullName = `${firstName} ${lastName}`.trim();
  const company = safe(personal.company || '', 80);
  const email = safe(contact.email || '', 120);
  const phone = safe(contact.phone || '', 50);

  // Use short code for QR URL (always use short code for simpler QR)
  const cardUrl = typeof window !== 'undefined' && shortCode
    ? `${window.location.origin}/${shortCode}`
    : '';

  // Build vCard 3.0 format (minimal for QR scanning reliability)
  let vcard = 'BEGIN:VCARD\nVERSION:3.0\n';

  if (fullName) {
    vcard += `FN:${fullName}\n`;
    vcard += `N:${lastName};${firstName};;;\n`;
  }

  if (company) {
    vcard += `ORG:${company}\n`;
  }

  if (email) {
    vcard += `EMAIL;TYPE=WORK:${email}\n`;
  }

  if (phone) {
    vcard += `TEL;TYPE=CELL:${phone}\n`;
  }

  if (cardUrl) {
    vcard += `URL:${cardUrl}\n`;
  }

  vcard += 'END:VCARD';

  return vcard;
};

const saveQrPayloadToStorage = (payload) => {
  try {
    if (!payload) return;
    const record = {
      payload,
      savedAt: new Date().toISOString()
    };
    localStorage.setItem(QR_STORAGE_KEY, JSON.stringify(record));
  } catch (e) {
    console.warn('Failed to save QR payload', e);
  }
};

const loadQrPayloadFromStorage = () => {
  try {
    const raw = localStorage.getItem(QR_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed?.payload || null;
  } catch (e) {
    console.warn('Failed to load QR payload', e);
    return null;
  }
};

export { QR_STORAGE_KEY, buildQrPayload, saveQrPayloadToStorage, loadQrPayloadFromStorage };
