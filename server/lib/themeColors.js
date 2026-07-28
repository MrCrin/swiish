// Helper function to map theme color name to hex (for SVG icon theming)
const getThemeColorHex = (colorName) => {
  if (!colorName || typeof colorName !== 'string') {
    return '#4f46e5'; // default to indigo
  }

  const normalizedColorName = colorName.toLowerCase().trim();
  const colorMap = {
    indigo: '#4f46e5',
    blue: '#2563eb',
    rose: '#e11d48',
    emerald: '#059669',
    slate: '#475569',
    purple: '#7c3aed',
    cyan: '#0891b2',
    teal: '#0d9488',
    orange: '#ea580c',
    pink: '#db2777',
    violet: '#7c3aed',
    fuchsia: '#c026d3',
    amber: '#d97706',
    lime: '#65a30d',
    green: '#16a34a',
    yellow: '#ca8a04',
    red: '#dc2626'
  };

  return colorMap[normalizedColorName] || '#4f46e5';
};

// Helper function to get default theme colours (hex-only format)
const getDefaultThemeColors = () => [
  {
    name: "indigo",
    colorType: "standard",
    baseColor: "indigo",
    hexBase: "#4f46e5",
    hexSecondary: "#7c3aed",
    gradientStyle: "linear-gradient(135deg, #4f46e5, #7c3aed)",
    buttonStyle: "#4f46e5",
    linkStyle: "#4f46e5",
    textStyle: "#4f46e5"
  },
  {
    name: "blue",
    colorType: "standard",
    baseColor: "blue",
    hexBase: "#2563eb",
    hexSecondary: "#0891b2",
    gradientStyle: "linear-gradient(135deg, #2563eb, #0891b2)",
    buttonStyle: "#2563eb",
    linkStyle: "#2563eb",
    textStyle: "#2563eb"
  },
  {
    name: "rose",
    colorType: "standard",
    baseColor: "rose",
    hexBase: "#e11d48",
    hexSecondary: "#ea580c",
    gradientStyle: "linear-gradient(135deg, #e11d48, #ea580c)",
    buttonStyle: "#e11d48",
    linkStyle: "#e11d48",
    textStyle: "#e11d48"
  },
  {
    name: "emerald",
    colorType: "standard",
    baseColor: "emerald",
    hexBase: "#059669",
    hexSecondary: "#0d9488",
    gradientStyle: "linear-gradient(135deg, #059669, #0d9488)",
    buttonStyle: "#059669",
    linkStyle: "#059669",
    textStyle: "#059669"
  },
  {
    name: "slate",
    colorType: "standard",
    baseColor: "slate",
    hexBase: "#475569",
    hexSecondary: "#475569",
    gradientStyle: "linear-gradient(135deg, #475569, #475569)",
    buttonStyle: "#475569",
    linkStyle: "#475569",
    textStyle: "#475569"
  }
];

module.exports = {
  getThemeColorHex,
  getDefaultThemeColors,
};
