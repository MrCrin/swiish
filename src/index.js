import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App';
const swiishTheme = require('./theme/swiish');

// Helper to convert camelCase to kebab-case
const toKebabCase = (str) => str.replace(/([A-Z])/g, (match) => '-' + match).toLowerCase();

// Initialize CSS custom properties from theme
// This ensures the page looks correct before React loads
const initializeThemeVars = (theme) => {
  const root = document.documentElement;
  const colors = theme.colors || {};
  
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
  
  // Surface textures
  root.style.setProperty('--texture-surface-light', 
    theme.textures?.surface?.light ? `url(${theme.textures.surface.light})` : 'none');
  root.style.setProperty('--texture-surface-dark', 
    theme.textures?.surface?.dark ? `url(${theme.textures.surface.dark})` : 'none');
  
  // Card textures
  root.style.setProperty('--texture-card-light', 
    theme.textures?.card?.light ? `url(${theme.textures.card.light})` : 'none');
  root.style.setProperty('--texture-card-dark', 
    theme.textures?.card?.dark ? `url(${theme.textures.card.dark})` : 'none');
};

// Initialize with swiish theme before rendering
initializeThemeVars(swiishTheme);

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) {
    return;
  }

  // In production builds, webpack replaces process.env.NODE_ENV with the string "production"
  // In development mode (npm start), it's "development"
  // This is the most reliable way to detect production builds
  const isProductionBuild = process.env.NODE_ENV === 'production';
  
  if (isProductionBuild) {
    // Register service worker in production builds (works on localhost and live servers)
    window.addEventListener('load', () => {
      const swUrl = `${process.env.PUBLIC_URL || ''}/service-worker.js`;
      
      navigator.serviceWorker
        .register(swUrl)
        .catch((error) => {
          console.error('Service worker registration failed:', error);
        });
    });
  } else {
    // Unregister any existing service workers in development mode
    // This prevents caching issues during local development with npm start
    navigator.serviceWorker.getRegistrations().then((registrations) => {
      registrations.forEach((registration) => {
        registration.unregister();
      });
    });
  }
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);

registerServiceWorker();
