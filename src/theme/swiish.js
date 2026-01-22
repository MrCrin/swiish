// Swiish Design Tokens
// Centralized theme configuration - change values here to restyle the entire site
// Only includes values actually used in the application

const tailwindColors = require('tailwindcss/colors');

module.exports = {
  // Colors
  colors: {
    // Main backgrounds
    main: {
      light: tailwindColors.stone[50],   // Main page background (light theme)
      dark: tailwindColors.zinc[900],     // Main page background (dark theme)
    },
    
    // Card backgrounds
    card: {
      light: tailwindColors.stone[200],       // Card backgrounds, modals (light theme)
      dark: tailwindColors.zinc[800],     // Card backgrounds, modals (dark theme)
    },
    
    // Secondary card/surface backgrounds
    surface: {
      light: tailwindColors.stone[300],   // Secondary backgrounds, setup/login pages (light theme)
      dark: tailwindColors.zinc[700],     // Input fields, secondary cards (dark theme)
    },
    
    // Primary action button
    action: {
      light: tailwindColors.violet[800],  // Primary buttons (light theme)
      dark: tailwindColors.fuchsia[800],   // Primary buttons (dark theme)
    },
    
    // Primary action button hover
    actionHover: {
      light: tailwindColors.violet[600],  // Button hover states (light theme)
      dark: tailwindColors.fuchsia[500],   // Button hover states (dark theme)
    },
    
    // Primary text
    textPrimary: {
      light: tailwindColors.zinc[800],   // Headings (light theme)
      dark: tailwindColors.stone[100],    // Headings, primary text (dark theme)
    },
    
    // Secondary text
    textSecondary: {
      light: tailwindColors.zinc[700],   // Body text, buttons (light theme)
      dark: tailwindColors.stone[300],    // Body text, buttons (dark theme)
    },
    
    // Muted text
    textMuted: {
      light: tailwindColors.zinc[600],   // Secondary text, descriptions (light theme)
      dark: tailwindColors.stone[300],    // Secondary text, descriptions (dark theme)
    },
    
    // Very muted text
    textMutedSubtle: {
      light: tailwindColors.zinc[500],   // Muted text, placeholders (light theme)
      dark: tailwindColors.zinc[500],    // Muted text (dark theme)
    },
    
    // Borders
    border: {
      light: tailwindColors.stone[400],   // Default borders (light theme)
      dark: tailwindColors.zinc[700],     // Default borders (dark theme)
    },
    
    // Borders (subtle)
    borderSubtle: {
      light: tailwindColors.stone[300],   // Subtle borders (light theme)
      dark: tailwindColors.zinc[600],     // Subtle borders (dark theme)
    },
    
    // Success
    success: {
      light: tailwindColors.emerald[600], // Success buttons (light theme)
      dark: tailwindColors.emerald[500],  // Success buttons (dark theme)
    },
    
    successHover: {
      light: tailwindColors.emerald[700], // Success hover states (light theme)
      dark: tailwindColors.emerald[600],  // Success hover states (dark theme)
    },
    
    successBg: {
      light: tailwindColors.emerald[50],  // Success backgrounds (light theme)
      dark: `rgba(6, 78, 59, 0.3)`,       // emerald-900 with opacity (dark theme)
    },
    
    successText: {
      light: tailwindColors.emerald[500], // Success text, icons (light theme)
      dark: tailwindColors.emerald[400],   // Success icons (dark theme)
    },
    
    successBorder: {
      light: tailwindColors.emerald[200], // Success borders (light theme)
      dark: tailwindColors.emerald[800],  // Success borders (dark theme)
    },
    
    // Error/Destructive
    error: {
      light: tailwindColors.rose[600],    // Error buttons, destructive actions (light theme)
      dark: tailwindColors.rose[500],     // Error buttons (dark theme)
    },
    
    errorHover: {
      light: tailwindColors.rose[700],    // Error hover states (light theme)
      dark: tailwindColors.rose[600],      // Error hover states (dark theme)
    },
    
    errorBg: {
      light: tailwindColors.rose[50],     // Error backgrounds (light theme)
      dark: `rgba(136, 19, 55, 0.3)`,     // rose-900 with opacity (dark theme)
    },
    
    errorText: {
      light: tailwindColors.rose[500],    // Error text, icons (light theme)
      dark: tailwindColors.rose[400],     // Error icons (dark theme)
    },
    
    errorBorder: {
      light: tailwindColors.rose[200],    // Error borders (light theme)
      dark: tailwindColors.rose[800],     // Error borders (dark theme)
    },
    
    // Info
    info: {
      light: tailwindColors.sky[900],    // Info buttons (light theme)
      dark: tailwindColors.sky[900],     // Info buttons (dark theme)
    },
    
    infoHover: {
      light: tailwindColors.sky[700],    // Info hover states (light theme)
      dark: tailwindColors.sky[600],     // Info hover states (dark theme)
    },
    
    infoBg: {
      light: tailwindColors.sky[50],     // Info backgrounds (light theme)
      dark: `rgba(30, 58, 138, 0.3)`,     // sky-900 with opacity (dark theme)
    },
    
    infoText: {
      light: tailwindColors.sky[500],    // Info text, icons (light theme)
      dark: tailwindColors.sky[400],      // Info icons (dark theme)
    },
    
    infoBorder: {
      light: tailwindColors.sky[200],    // Info borders (light theme)
      dark: tailwindColors.sky[800],     // Info borders (dark theme)
    },
    
    // Link colors
    link: {
      light: tailwindColors.indigo[600],  // Link text (light theme)
      dark: tailwindColors.indigo[400],   // Link text (dark theme)
    },
    
    linkBg: {
      light: tailwindColors.indigo[50],   // Link backgrounds (light theme)
      dark: `rgba(99, 102, 241, 0.3)`,   // indigo-500 with opacity (dark theme)
    },
    
    linkBorder: {
      light: tailwindColors.indigo[100],  // Link borders (light theme)
      dark: tailwindColors.indigo[800],    // Link borders (dark theme)
    },
    
    linkHover: {
      light: tailwindColors.indigo[100],  // Link hover backgrounds (light theme)
      dark: tailwindColors.indigo[800],   // Link hover (dark theme)
    },
    
    // Input fields
    inputBg: {
      light: tailwindColors.white,        // Input backgrounds (light theme)
      dark: tailwindColors.zinc[700],     // Input backgrounds (dark theme)
    },
    
    inputBorder: {
      light: tailwindColors.zinc[200],   // Input borders (light theme)
      dark: tailwindColors.zinc[700],     // Input borders (dark theme)
    },
    
    inputText: {
      light: tailwindColors.zinc[900],   // Input text (light theme)
      dark: tailwindColors.zinc[100],    // Input text (dark theme)
    },
    
    // Focus ring
    focusRing: {
      light: tailwindColors.zinc[600],    // indigo-600 with opacity (light theme)
      dark: tailwindColors.white,   // indigo-400 with opacity (dark theme)
    },
    
    // Modal overlay
    overlay: {
      light: `rgba(0, 0, 0, 0.6)`,        // Modal overlay (light theme)
      dark: `rgba(0, 0, 0, 0.8)`,         // Modal overlay (dark theme)
    },
    
    // Confirm/Neutral button
    confirm: {
      light: tailwindColors.zinc[900],   // Confirm button (light theme)
      dark: tailwindColors.zinc[400],    // Confirm button (dark theme)
    },
    
    confirmHover: {
      light: tailwindColors.zinc[800],   // Confirm hover (light theme)
      dark: tailwindColors.zinc[200],    // Confirm hover (dark theme)
    },
    
    confirmText: {
      light: tailwindColors.white,        // Confirm text (light theme)
      dark: tailwindColors.zinc[900],    // Confirm text (dark theme)
    },
    
    confirmBg: {
      light: tailwindColors.zinc[50],    // Confirm backgrounds (light theme)
      dark: tailwindColors.zinc[700],    // Confirm backgrounds (dark theme)
    },
    
    confirmBorder: {
      light: tailwindColors.zinc[200],   // Confirm borders (light theme)
      dark: tailwindColors.zinc[600],    // Confirm borders (dark theme)
    },
  },

  // Border Radius (corner radius)
  // Used for: rounded-card, rounded-container, rounded-button, rounded-input, rounded-badge, rounded-full
  borderRadius: {
    'card': '40px',        // Cards, modals (equivalent to rounded-2xl)
    'container': '25px',   // Simple containers, info boxes (equivalent to rounded-lg)
    'page': '1.5rem',      // Setup/login pages (equivalent to rounded-3xl)
    'button': '9999px',    // Buttons (equivalent to rounded-full)
    'input': '0.75rem',    // Input fields (equivalent to rounded-xl)
    'badge': '6px',        // Badges, labels like "owner", "member" (small rounded corners)
    'full': '9999px',      // Full circle (equivalent to rounded-full)
  },

  // Border Width (thickness)
  // Used for: border-default, border-thick, border-avatar, border-device
  borderWidth: {
    'default': '1px',      // Default borders (standard border)
    'thick': '2px',        // Thick borders (border-2)
    'avatar': '6px',       // Avatar borders (border-[6px])
    'device': '8px',       // Device preview borders (border-8)
  },

  // Background Textures
  // Set to empty string ('') to disable texture for that background
  // Paths are relative to public folder
  textures: {
    main: {
      light: '/textures/sandTexture.jpg',  // Main background texture (light theme)
      dark: '/textures/sandTexture.jpg',   // Main background texture (dark theme)
      size: '1080px 1080px',                 // Texture tile size
      blendLight: 'multiply',              // Blend mode for light theme
      blendDark: 'overlay',                // Blend mode for dark theme
      opacityLight: 0.07,                  // Texture opacity for light theme
      opacityDark: 0.20,                   // Texture opacity for dark theme
    },
    surface: {
      light: '',  // Surface background texture (light theme) - empty = no texture
      dark: '',   // Surface background texture (dark theme) - empty = no texture
    },
    card: {
      light: '',  // Card background texture (light theme) - empty = no texture
      dark: '',   // Card background texture (dark theme) - empty = no texture
    },
  },
};

