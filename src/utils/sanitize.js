import DOMPurify from 'dompurify';

// Helper function to sanitize text content
const sanitizeText = (text) => {
  if (!text) return '';
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [] });
};

// Helper function to sanitize HTML content (for bio)
const sanitizeHTML = (html) => {
  if (!html) return '';
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u'],
    ALLOWED_ATTR: []
  });
};

export { sanitizeText, sanitizeHTML };
