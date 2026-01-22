// Minimal theme: black/white with very limited grays, no textures.
const tailwindColors = require('tailwindcss/colors');

module.exports = {
  colors: {
    main: {
      light: tailwindColors.stone[50],
      dark: tailwindColors.zinc[950],
    },
    card: {
      light: tailwindColors.stone[50],
      dark: tailwindColors.zinc[950],
    },
    surface: {
      light: tailwindColors.stone[50],
      dark: tailwindColors.zinc[950],
    },
    action: {
      light: tailwindColors.violet[900],
      dark: tailwindColors.stone[50],
    },
    actionHover: {
      light: tailwindColors.stone[50],
      dark: tailwindColors.violet[900],
    },
    textPrimary: {
      light: tailwindColors.zinc[900],
      dark: tailwindColors.stone[50],
    },
    textSecondary: {
      light: tailwindColors.zinc[900],
      dark: tailwindColors.stone[50],
    },
    textMuted: {
      light: tailwindColors.zinc[900],
      dark: tailwindColors.stone[50],
    },
    textMutedSubtle: {
      light: tailwindColors.zinc[900],
      dark: tailwindColors.stone[50],
    },
    border: {
      light: tailwindColors.zinc[500],
      dark: tailwindColors.stone[400],
    },
    borderSubtle: {
      light: tailwindColors.zinc[500],
      dark: tailwindColors.stone[500],
    },
    success: {
      light: tailwindColors.emerald[600],
      dark: tailwindColors.emerald[500],
    },
    successHover: {
      light: tailwindColors.emerald[700],
      dark: tailwindColors.emerald[600],
    },
    successBg: {
      light: tailwindColors.emerald[50],
      dark: 'rgba(6, 78, 59, 0.3)',
    },
    successText: {
      light: tailwindColors.emerald[500],
      dark: tailwindColors.emerald[400],
    },
    successBorder: {
      light: tailwindColors.emerald[200],
      dark: tailwindColors.emerald[800],
    },
    error: {
      light: tailwindColors.rose[600],
      dark: tailwindColors.rose[500],
    },
    errorHover: {
      light: tailwindColors.rose[700],
      dark: tailwindColors.rose[600],
    },
    errorBg: {
      light: tailwindColors.rose[50],
      dark: 'rgba(136, 19, 55, 0.3)',
    },
    errorText: {
      light: tailwindColors.rose[500],
      dark: tailwindColors.rose[400],
    },
    errorBorder: {
      light: tailwindColors.rose[200],
      dark: tailwindColors.rose[800],
    },
    info: {
      light: tailwindColors.blue[600],
      dark: tailwindColors.blue[500],
    },
    infoHover: {
      light: tailwindColors.blue[700],
      dark: tailwindColors.blue[600],
    },
    infoBg: {
      light: tailwindColors.blue[50],
      dark: 'rgba(30, 58, 138, 0.3)',
    },
    infoText: {
      light: tailwindColors.blue[500],
      dark: tailwindColors.blue[400],
    },
    infoBorder: {
      light: tailwindColors.blue[200],
      dark: tailwindColors.blue[800],
    },
    link: {
      light: '#0f1115',
      dark: '#f5f5f5',
    },
    linkBg: {
      light: 'transparent',
      dark: 'transparent',
    },
    linkBorder: {
      light: '#d4d4d8',
      dark: '#2f2f33',
    },
    linkHover: {
      light: '#e4e4e7',
      dark: '#1f1f23',
    },
    inputBg: {
      light: '#ffffff',
      dark: '#111114',
    },
    inputBorder: {
      light: '#d4d4d8',
      dark: '#2f2f33',
    },
    inputText: {
      light: '#0f1115',
      dark: '#f5f5f5',
    },
    focusRing: {
      light: 'rgba(17, 17, 17, 0.15)',
      dark: 'rgba(245, 245, 245, 0.15)',
    },
    overlay: {
      light: 'rgba(0,0,0,0.55)',
      dark: 'rgba(0,0,0,0.75)',
    },
    confirm: {
      light: '#111111',
      dark: '#f5f5f5',
    },
    confirmHover: {
      light: '#1f1f1f',
      dark: '#e5e5e5',
    },
    confirmText: {
      light: '#ffffff',
      dark: '#0b0b0d',
    },
    confirmBg: {
      light: '#f7f7f8',
      dark: '#111114',
    },
    confirmBorder: {
      light: '#d4d4d8',
      dark: '#2f2f33',
    },
  },
  borderRadius: {
    card: '40px',
    container: '25px',
    page: '1.5rem',
    button: '9999px',
    input: '0.75rem',
    badge: '6px',
    full: '9999px',
  },
  borderWidth: {
    default: '1px',
    thick: '2px',
    avatar: '6px',
    device: '8px',
  },
  textures: {
    main: { light: '', dark: '', size: '0', blendLight: 'normal', blendDark: 'normal', opacityLight: 0, opacityDark: 0 },
    surface: { light: '', dark: '' },
    card: { light: '', dark: '' },
  },
};

