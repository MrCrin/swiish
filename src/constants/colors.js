// --- STYLES ---
// Helper functions to get color classes from settings
const getThemeGradient = (colorName, settings) => {
  if (!settings?.theme_colors) return "linear-gradient(135deg, #4f46e5, #7c3aed)";
  const color = settings.theme_colors.find(c => c.name === colorName);
  return color?.gradientStyle || "linear-gradient(135deg, #4f46e5, #7c3aed)";
};

const getButtonColor = (colorName, settings) => {
  if (!settings?.theme_colors) return "#4f46e5";
  const color = settings.theme_colors.find(c => c.name === colorName);
  return color?.buttonStyle || "#4f46e5";
};

const getLinkColor = (colorName, settings) => {
  if (!settings?.theme_colors) return "#4f46e5";
  const color = settings.theme_colors.find(c => c.name === colorName);
  return color?.linkStyle || "#4f46e5";
};

const getTextColor = (colorName, settings) => {
  if (!settings?.theme_colors) return "#4f46e5";
  const color = settings.theme_colors.find(c => c.name === colorName);
  return color?.textStyle || "#4f46e5";
};

// --- COLOR GENERATION UTILITIES ---
const TAILWIND_COLORS = ['indigo', 'blue', 'rose', 'emerald', 'slate', 'purple', 'cyan', 'teal', 'orange', 'pink', 'violet', 'fuchsia', 'amber', 'lime', 'green', 'yellow', 'red'];

const COMPLEMENTARY_MAP = {
  indigo: 'purple',
  blue: 'cyan',
  rose: 'orange',
  emerald: 'teal',
  slate: 'slate',
  purple: 'indigo',
  cyan: 'blue',
  teal: 'emerald',
  orange: 'rose',
  pink: 'fuchsia',
  violet: 'purple',
  fuchsia: 'pink',
  amber: 'orange',
  lime: 'green',
  green: 'emerald',
  yellow: 'amber',
  red: 'rose'
};

const getComplementaryColor = (baseColor) => {
  return COMPLEMENTARY_MAP[baseColor] || 'purple';
};

const getTailwindShades = () => {
  return [400, 500, 600, 700, 800];
};

// Tailwind color to hex mapping (for common shades)
const TAILWIND_TO_HEX = {
  indigo: { 400: '#818cf8', 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca', 800: '#3730a3' },
  blue: { 400: '#60a5fa', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8', 800: '#1e40af' },
  rose: { 400: '#fb7185', 500: '#f43f5e', 600: '#e11d48', 700: '#be123c', 800: '#9f1239' },
  emerald: { 400: '#34d399', 500: '#10b981', 600: '#059669', 700: '#047857', 800: '#065f46' },
  slate: { 400: '#94a3b8', 500: '#64748b', 600: '#475569', 700: '#334155', 800: '#1e293b' },
  purple: { 400: '#a78bfa', 500: '#8b5cf6', 600: '#7c3aed', 700: '#6d28d9', 800: '#5b21b6' },
  cyan: { 400: '#22d3ee', 500: '#06b6d4', 600: '#0891b2', 700: '#0e7490', 800: '#155e75' },
  teal: { 400: '#2dd4bf', 500: '#14b8a6', 600: '#0d9488', 700: '#0f766e', 800: '#115e59' },
  orange: { 400: '#fb923c', 500: '#f97316', 600: '#ea580c', 700: '#c2410c', 800: '#9a3412' },
  pink: { 400: '#f472b6', 500: '#ec4899', 600: '#db2777', 700: '#be185d', 800: '#9f1239' },
  violet: { 400: '#a78bfa', 500: '#8b5cf6', 600: '#7c3aed', 700: '#6d28d9', 800: '#5b21b6' },
  fuchsia: { 400: '#f0abfc', 500: '#d946ef', 600: '#c026d3', 700: '#a21caf', 800: '#86198f' },
  amber: { 400: '#fbbf24', 500: '#f59e0b', 600: '#d97706', 700: '#b45309', 800: '#92400e' },
  lime: { 400: '#a3e635', 500: '#84cc16', 600: '#65a30d', 700: '#4d7c0f', 800: '#365314' },
  green: { 400: '#4ade80', 500: '#22c55e', 600: '#16a34a', 700: '#15803d', 800: '#166534' },
  yellow: { 400: '#facc15', 500: '#eab308', 600: '#ca8a04', 700: '#a16207', 800: '#854d0e' },
  red: { 400: '#f87171', 500: '#ef4444', 600: '#dc2626', 700: '#b91c1c', 800: '#991b1b' }
};

const getTailwindColorHex = (colorName, shade = 600) => {
  return TAILWIND_TO_HEX[colorName]?.[shade] || '#4f46e5';
};

// Utility to darken a hex color
const darkenHex = (hex, percent) => {
  // Remove # if present
  hex = hex.replace('#', '');

  // Convert to RGB
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);

  // Darken by percent
  const factor = 1 - (percent / 100);
  const newR = Math.max(0, Math.floor(r * factor));
  const newG = Math.max(0, Math.floor(g * factor));
  const newB = Math.max(0, Math.floor(b * factor));

  // Convert back to hex
  const toHex = (n) => {
    const hex = n.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  };

  return `#${toHex(newR)}${toHex(newG)}${toHex(newB)}`;
};


// Extract base color from existing gradient class (for migration)
const extractBaseColorFromGradient = (gradient) => {
  if (!gradient) return null;
  const match = gradient.match(/from-(\w+)-(\d+)/);
  if (match) {
    return { baseColor: match[1], shade: parseInt(match[2]) };
  }
  return null;
};

export {
  getThemeGradient,
  getButtonColor,
  getLinkColor,
  getTextColor,
  TAILWIND_COLORS,
  COMPLEMENTARY_MAP,
  getComplementaryColor,
  getTailwindShades,
  TAILWIND_TO_HEX,
  getTailwindColorHex,
  darkenHex,
  extractBaseColorFromGradient,
};
