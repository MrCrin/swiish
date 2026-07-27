const swiishTheme = require('../theme/swiish');
const minimalTheme = require('../theme/minimal');
const THEME_FILES = { swiish: swiishTheme, minimal: minimalTheme };

const THEME_PRESETS = {
  swiish: [
    { name: "indigo", gradient: "from-indigo-600 to-purple-600", button: "bg-indigo-600 hover:bg-indigo-700", link: "text-indigo-600 bg-indigo-50 border-indigo-100 hover:bg-indigo-100", text: "text-indigo-600" },
    { name: "blue", gradient: "from-blue-600 to-cyan-600", button: "bg-blue-600 hover:bg-blue-700", link: "text-blue-600 bg-blue-50 border-blue-100 hover:bg-blue-100", text: "text-blue-600" },
    { name: "rose", gradient: "from-rose-500 to-orange-500", button: "bg-rose-600 hover:bg-rose-700", link: "text-rose-600 bg-rose-50 border-rose-100 hover:bg-rose-100", text: "text-rose-600" },
    { name: "emerald", gradient: "from-emerald-500 to-teal-500", button: "bg-emerald-600 hover:bg-emerald-700", link: "text-emerald-600 bg-emerald-50 border-emerald-100 hover:bg-emerald-100", text: "text-emerald-600" },
    { name: "slate", gradient: "from-slate-700 to-slate-900", button: "bg-slate-800 hover:bg-slate-900", link: "text-slate-700 bg-border-subtle border-slate-200 hover:bg-slate-200", text: "text-slate-800" }
  ],
  minimal: [
    { name: "mono-dark", gradient: "from-neutral-900 to-neutral-700", button: "bg-neutral-900 hover:bg-neutral-800", link: "text-neutral-900 bg-neutral-100 border-neutral-200 hover:bg-neutral-200", text: "text-neutral-900" },
    { name: "mono-mid", gradient: "from-neutral-700 to-neutral-500", button: "bg-neutral-700 hover:bg-neutral-600", link: "text-neutral-700 bg-neutral-50 border-neutral-200 hover:bg-neutral-100", text: "text-neutral-700" },
    { name: "mono-light", gradient: "from-neutral-300 to-neutral-200", button: "bg-neutral-200 hover:bg-neutral-300 text-neutral-900", link: "text-neutral-700 bg-white border-neutral-200 hover:bg-neutral-100", text: "text-neutral-700" }
  ]
};

// Define applyThemeCssVars outside component to ensure it's always available
// This function sets all CSS custom properties from the selected theme file
const applyThemeCssVars = (variant) => {
  const root = document.documentElement;
  const theme = THEME_FILES[variant] || swiishTheme;
  const colors = theme.colors || {};

  // Helper to convert camelCase to kebab-case
  const toKebabCase = (str) => str.replace(/([A-Z])/g, (match) => '-' + match).toLowerCase();

  // Set all color CSS variables from theme
  Object.keys(colors).forEach((colorKey) => {
    const colorValue = colors[colorKey];
    if (colorValue && typeof colorValue === 'object' && colorValue.light !== undefined) {
      const cssVarName = `--color-${toKebabCase(colorKey)}`;
      root.style.setProperty(`${cssVarName}-light`, colorValue.light);
      root.style.setProperty(`${cssVarName}-dark`, colorValue.dark);
    }
  });

  // Set texture variables
  const textures = theme.textures?.main || {};
  root.style.setProperty('--texture-main-light', textures.light ? `url(${textures.light})` : 'none');
  root.style.setProperty('--texture-main-dark', textures.dark ? `url(${textures.dark})` : 'none');
  root.style.setProperty('--texture-main-size', textures.size || '540px 540px');
  root.style.setProperty('--texture-main-blend-light', textures.blendLight || 'multiply');
  root.style.setProperty('--texture-main-blend-dark', textures.blendDark || 'overlay');
  root.style.setProperty('--texture-main-opacity-light', textures.opacityLight ?? 0.08);
  root.style.setProperty('--texture-main-opacity-dark', textures.opacityDark ?? 0.1);
};

export { swiishTheme, minimalTheme, THEME_FILES, THEME_PRESETS, applyThemeCssVars };
