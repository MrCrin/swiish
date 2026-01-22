import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Routes, Route, useNavigate, useLocation, useParams } from 'react-router-dom';
import DOMPurify from 'dompurify';
import PhoneInput from 'react-phone-number-input';
import 'react-phone-number-input/style.css';
import flags from 'country-flag-icons/react/3x2';
import { 
  Camera, Upload, Save, Share2, Phone, Mail, Globe, 
  Linkedin, Twitter, Instagram, Github, Edit3, Eye, 
  X, Check, User, MapPin, Briefcase, Lock, LogIn, AlertCircle, 
  Plus, Trash2, ArrowLeft, Users, ExternalLink, RefreshCw,
  Download, FileText, Calendar, Video, Music, ShoppingCart, 
  Link as LinkIcon, Youtube, Facebook, MessageCircle, Sun, Moon,
  ChevronUp, ChevronDown, GripVertical, Settings
} from 'lucide-react';
import { DndContext, PointerSensor, closestCenter, useSensor, useSensors } from '@dnd-kit/core';
import { SortableContext, verticalListSortingStrategy, useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { arrayMove } from '@dnd-kit/sortable';

const API_ENDPOINT = '/api';
const APP_VERSION = require('../package.json').version; // Automatically read from package.json
const GITHUB_URL = 'https://github.com/MrCrin/swiish';

// Try to read branch info from active-branch.json (generated at build time)
let GIT_BRANCH = null;
try {
  const branchInfo = require('./active-branch.json');
  GIT_BRANCH = branchInfo.branch;
} catch (e) {
  // active-branch.json doesn't exist yet (first run before build)
  GIT_BRANCH = null;
}
const swiishTheme = require('./theme/swiish');
const minimalTheme = require('./theme/minimal');
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

// --- ICONS MAPPING ---
const ICON_MAP = {
  link: LinkIcon,
  download: Download,
  file: FileText,
  calendar: Calendar,
  video: Video,
  music: Music,
  shop: ShoppingCart,
  youtube: Youtube,
  facebook: Facebook,
  whatsapp: MessageCircle,
  globe: Globe
};

// --- DATA TEMPLATE ---
const getDefaultTemplate = (settings) => ({
  personal: {
    firstName: "New",
    lastName: "User",
    title: "Role Title",
    company: settings?.default_organisation || "My Organisation",
    bio: "Welcome to the team.",
    location: "London, UK"
  },
  contact: {
    email: "",
    phone: "",
    website: "",
  },
  social: { linkedin: "", twitter: "", instagram: "", github: "" },
  theme: { color: "indigo", style: "modern" },
  images: { avatar: null, banner: null },
  links: [],
  privacy: {
    requireInteraction: true,  // ON by default
    clientSideObfuscation: false,  // OFF by default
    blockRobots: false  // OFF by default
  }
});

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

// Modal Component
function Modal({ isOpen, onClose, type = 'info', title, message, onConfirm, confirmText = 'OK', cancelText = 'Cancel', inputLabel, inputPlaceholder, inputValue, onInputChange }) {
  if (!isOpen) return null;

  const typeStyles = {
    info: { icon: AlertCircle, iconColor: 'text-info-text dark:text-info-text-dark', bgColor: 'bg-info-bg dark:bg-info-bg-dark', borderColor: 'border-info-border dark:border-info-border-dark' },
    success: { icon: Check, iconColor: 'text-success-text dark:text-success-text-dark', bgColor: 'bg-success-bg dark:bg-success-bg-dark', borderColor: 'border-success-border dark:border-success-border-dark' },
    error: { icon: AlertCircle, iconColor: 'text-error-text dark:text-error-text-dark', bgColor: 'bg-error-bg dark:bg-error-bg-dark', borderColor: 'border-error-border dark:border-error-border-dark' },
    confirm: { icon: AlertCircle, iconColor: 'text-text-muted dark:text-text-muted-dark', bgColor: 'bg-surface dark:bg-surface-dark', borderColor: 'border-border dark:border-border-dark' }
  };

  const style = typeStyles[type] || typeStyles.info;
  const Icon = style.icon;
  const hasInput = inputLabel || inputPlaceholder;

  const handleConfirm = () => {
    if (onConfirm) {
      onConfirm();
    }
    // onClose will handle calling the onClose callback
    onClose();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && hasInput) {
      handleConfirm();
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 dark:bg-black/80 backdrop-blur-sm z-[100] flex items-center justify-center p-4" onClick={onClose}>
      <div 
        className="bg-card dark:bg-card-dark rounded-card shadow-2xl max-w-sm w-full p-6 animate-in fade-in duration-200" 
        onClick={(e) => e.stopPropagation()}
      >
        <div className={`w-12 h-12 rounded-full ${style.bgColor} flex items-center justify-center mx-auto mb-4`}>
          <Icon className={`w-6 h-6 ${style.iconColor}`} />
        </div>
        {title && <h3 className="text-xl font-bold text-text-primary dark:text-text-primary-dark text-center mb-2">{title}</h3>}
        {message && <p className="text-text-secondary dark:text-text-secondary-dark text-center mb-6">{message}</p>}
        {hasInput && (
          <div className="mb-6">
            {inputLabel && <label className="block text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2">{inputLabel}</label>}
            <input
              type="text"
              value={inputValue || ''}
              onChange={(e) => onInputChange && onInputChange(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={inputPlaceholder}
              className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
              autoFocus
            />
          </div>
        )}
        <div className="flex gap-3">
          {(type === 'confirm' || hasInput) && (
            <button
              onClick={onClose}
              className="flex-1 px-4 py-2.5 rounded-full font-medium text-text-secondary dark:text-text-secondary-dark bg-surface dark:bg-surface-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors"
            >
              {cancelText}
            </button>
          )}
          <button
            onClick={handleConfirm}
            className={`flex-1 px-4 py-2.5 rounded-full font-bold text-white transition-colors ${
              type === 'error' ? 'bg-error dark:bg-error-dark hover:bg-error-hover dark:hover:bg-error-hover-dark' :
              type === 'success' ? 'bg-success dark:bg-success-dark hover:bg-success-hover dark:hover:bg-success-hover-dark' :
              type === 'confirm' ? 'bg-confirm dark:bg-confirm-dark hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark text-confirm-text dark:text-confirm-text-dark' :
              'bg-info dark:bg-info-dark hover:bg-info-hover dark:hover:bg-info-hover-dark'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

function VersionBadge() {
  const [isOutdated, setIsOutdated] = useState(false);
  const [isAhead, setIsAhead] = useState(false);
  const [isChecking, setIsChecking] = useState(true);
  
  // Determine if we're on a non-release branch
  // Show branch name if it's not main, master, or a version tag pattern (e.g., v0.3.1)
  const isReleaseBranch = !GIT_BRANCH || 
    GIT_BRANCH === 'main' || 
    GIT_BRANCH === 'master' || 
    /^v?\d+\.\d+/.test(GIT_BRANCH) ||
    GIT_BRANCH === 'HEAD'; // Detached HEAD state (common in CI/Docker)
  
  const showBranch = GIT_BRANCH && !isReleaseBranch;

  useEffect(() => {
    // Check GitHub for latest version
    const checkVersion = async () => {
      try {
        const response = await fetch('https://api.github.com/repos/MrCrin/swiish/releases/latest', {
          headers: {
            'Accept': 'application/vnd.github.v3+json'
          }
        });
        
        if (response.ok) {
          const data = await response.json();
          const latestVersion = data.tag_name?.replace(/^v/, '') || data.tag_name; // Remove 'v' prefix if present
          const currentVersion = APP_VERSION;
          
          // SemVer-compliant version comparison
          // Follows SemVer precedence rules: pre-release versions have lower precedence than stable versions
          const compareVersions = (v1, v2) => {
            // Parse versions into base version and pre-release identifier
            const parseVersion = (version) => {
              const dashIndex = version.indexOf('-');
              if (dashIndex === -1) {
                return {
                  base: version,
                  prerelease: null
                };
              }
              return {
                base: version.substring(0, dashIndex),
                prerelease: version.substring(dashIndex + 1)
              };
            };

            const parsed1 = parseVersion(v1);
            const parsed2 = parseVersion(v2);

            // Compare base versions numerically
            const base1 = parsed1.base.split('.').map(Number);
            const base2 = parsed2.base.split('.').map(Number);

            for (let i = 0; i < Math.max(base1.length, base2.length); i++) {
              const part1 = base1[i] || 0;
              const part2 = base2[i] || 0;
              if (part1 < part2) return -1;
              if (part1 > part2) return 1;
            }

            // Base versions are equal, now check pre-release identifiers
            // Rule: A version without a pre-release identifier has higher precedence
            if (parsed1.prerelease === null && parsed2.prerelease === null) {
              return 0; // Both are stable, equal
            }
            if (parsed1.prerelease === null) {
              return 1; // v1 is stable, v2 is pre-release, v1 > v2
            }
            if (parsed2.prerelease === null) {
              return -1; // v1 is pre-release, v2 is stable, v1 < v2
            }

            // Both have pre-release identifiers, compare lexicographically
            const prerelease1 = parsed1.prerelease.split('.');
            const prerelease2 = parsed2.prerelease.split('.');

            for (let i = 0; i < Math.max(prerelease1.length, prerelease2.length); i++) {
              const part1 = prerelease1[i];
              const part2 = prerelease2[i];

              if (part1 === undefined) return -1; // v1 has fewer parts, v1 < v2
              if (part2 === undefined) return 1; // v2 has fewer parts, v1 > v2

              // Try numeric comparison first, fall back to string comparison
              const num1 = Number(part1);
              const num2 = Number(part2);

              if (!isNaN(num1) && !isNaN(num2)) {
                // Both are numeric
                if (num1 < num2) return -1;
                if (num1 > num2) return 1;
              } else {
                // At least one is non-numeric, compare as strings
                if (part1 < part2) return -1;
                if (part1 > part2) return 1;
              }
            }

            return 0; // Pre-release identifiers are equal
          };
          
          if (latestVersion) {
            const comparison = compareVersions(currentVersion, latestVersion);
            if (comparison < 0) {
              setIsOutdated(true);
            } else if (comparison > 0) {
              setIsAhead(true);
            }
          }
        }
      } catch (error) {
        console.error('Failed to check version:', error);
        // Silently fail - don't show error to user
      } finally {
        setIsChecking(false);
      }
    };

    checkVersion();
  }, []);

  // Build the display string: "v0.3.1" or "v0.3.1 (feature-branch)"
  const versionDisplay = showBranch 
    ? `v${APP_VERSION} (${GIT_BRANCH})`
    : `v${APP_VERSION}`;
  
  // Build the tooltip
  const tooltip = (!isOutdated && !isAhead && !showBranch)
    ? "You are on the latest release"
    : (isAhead || showBranch)
      ? "You are on an unreleased development version - things may break"
      : isOutdated
        ? "Update available on GitHub"
        : "View on GitHub";

  return (
    <div className="fixed bottom-4 left-4 z-50">
      <a
        href={GITHUB_URL}
        target="_blank"
        rel="noopener noreferrer"
        className={`text-xs font-medium transition-all bg-card dark:bg-card-dark border-2 border-border dark:border-border-dark px-2 py-1 rounded shadow-sm hover:shadow-md ${
          showBranch
            ? 'text-amber-600 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20 hover:border-amber-300 dark:hover:border-amber-700'
            : isOutdated 
              ? 'text-error-text dark:text-error-text-dark hover:bg-error-bg dark:hover:bg-error-bg-dark hover:border-error-border dark:hover:border-error-border-dark' 
              : isAhead
                ? 'text-info-text dark:text-info-text-dark hover:bg-info-bg dark:hover:bg-info-bg-dark hover:border-info-border dark:hover:border-info-border-dark'
                : 'text-text-primary dark:text-text-primary-dark hover:text-action dark:hover:text-action-dark hover:border-success-border dark:hover:border-success-border-dark'
        }`}
        title={tooltip}
      >
        {versionDisplay}
      </a>
    </div>
  );
}

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();
  // Note: useParams() doesn't work at App level (Routes are children), so we extract params from location.pathname
  const [view, setView] = useState(() => {
    // Initialize view based on current path - don't default to 'loading' for public routes
    const initialPath = typeof window !== 'undefined' ? window.location.pathname : '';
    const pathParts = initialPath.substring(1).split('/').filter(p => p);
    const isShortCode = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
    const isOrgScoped = pathParts.length === 2 && pathParts[0] && pathParts[1];
    const isPublicRoute = isShortCode || isOrgScoped || (pathParts.length === 1 && pathParts[0] && !initialPath.startsWith('/people') && !initialPath.startsWith('/login') && !initialPath.startsWith('/setup') && !initialPath.startsWith('/settings') && !initialPath.startsWith('/users') && !initialPath.startsWith('/cards') && initialPath !== '/');
    return isPublicRoute ? 'public-loading' : 'loading';
  }); 
  const [data, setData] = useState(() => getDefaultTemplate(null));
  const [currentSlug, setCurrentSlug] = useState('');
  const [isPublicLoading, setIsPublicLoading] = useState(false);
  const [cardList, setCardList] = useState([]);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState(null); // 'owner' or 'member'
  const [csrfToken, setCsrfToken] = useState('');
  const [error, setError] = useState('');
  const [modal, setModal] = useState({ isOpen: false, type: 'info', title: '', message: '', onConfirm: null, onClose: null, confirmText: 'OK', cancelText: 'Cancel' });
  const [createCardModal, setCreateCardModal] = useState({ isOpen: false, slug: '', userId: null });
  const [targetUserIdForNewCard, setTargetUserIdForNewCard] = useState(null);
  const [actionSelectionModal, setActionSelectionModal] = useState({ isOpen: false });
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [newUser, setNewUser] = useState({ email: '', password: '', role: 'member' });
  const [newInvitation, setNewInvitation] = useState({ email: '', role: 'member' });
  const [isSavingUser, setIsSavingUser] = useState(false);
  const [editingUserId, setEditingUserId] = useState(null);
  const [currentUserId, setCurrentUserId] = useState(null);
  const [currentUserEmail, setCurrentUserEmail] = useState(null);
  const [setupStatus, setSetupStatus] = useState(null);
  const [setupData, setSetupData] = useState({ organisationName: '', adminEmail: '', adminPassword: '' });
  const [isSettingUp, setIsSettingUp] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [isSuccessSetup, setIsSuccessSetup] = useState(false);
  const [isSuccessCreateUser, setIsSuccessCreateUser] = useState(false);
  const [isSuccessInvite, setIsSuccessInvite] = useState(false);
  
  // Demo mode state management
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [demoResetInterval, setDemoResetInterval] = useState(60);
  
  // Dark mode state management
  const [darkMode, setDarkMode] = useState(() => {
    const stored = localStorage.getItem('darkMode');
    if (stored !== null) {
      const isDark = stored === 'true';
      // Sync with document class immediately
      if (isDark) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
      return isDark;
    }
    // Use system preference
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (prefersDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    return prefersDark;
  });

  // Apply dark mode class to document whenever state changes
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  // Listen for system preference changes (only if no manual preference set)
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e) => {
      const stored = localStorage.getItem('darkMode');
      if (stored === null) {
        setDarkMode(e.matches);
      }
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // Check for demo mode on app load
  useEffect(() => {
    fetch(`${API_ENDPOINT}/demo/status`)
      .then(res => res.json())
      .then(data => {
        if (data.demoMode) {
          setIsDemoMode(true);
          setDemoResetInterval(data.resetInterval || 60);
        }
      })
      .catch(err => {
        // Silently fail - demo endpoint may not exist if demo mode is off
      });
  }, []);

  const toggleDarkMode = () => {
    const currentDark = document.documentElement.classList.contains('dark');
    const newValue = !currentDark;

    if (newValue) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }

    // Save to localStorage
    localStorage.setItem('darkMode', newValue.toString());

    // Update React state
    setDarkMode(newValue);

    setTimeout(() => {
      const sampleEl = document.querySelector('.bg-main');
      if (sampleEl) {
        void sampleEl.offsetHeight;
      }
    }, 100);
  };

  // Demo Mode Banner Component
  const DemoModeBanner = () => {
    if (!isDemoMode) return null;

    return (
      <div className="sticky top-0 left-0 right-0 z-50 bg-amber-100 dark:bg-amber-900 border-b-2 border-amber-400 dark:border-amber-700 px-4 py-3 text-center">
        <div className="flex items-center justify-center gap-3">
          <span className="text-2xl">🛠️</span>
          <span className="font-semibold text-amber-900 dark:text-amber-100">
            Demo Mode
          </span>
          <span className="text-sm text-amber-700 dark:text-amber-300">
            All changes reset every {demoResetInterval} minutes
          </span>
        </div>
      </div>
    );
  };

  // Helper functions to show modals
  const showAlert = (message, type = 'info', title = '', onClose = null) => {
    setModal({ isOpen: true, type, title, message, onConfirm: null, onClose, confirmText: 'OK', cancelText: 'Cancel' });
  };

  const showConfirm = (message, onConfirm, title = 'Confirm', confirmText = 'Confirm', cancelText = 'Cancel') => {
    setModal({ isOpen: true, type: 'confirm', title, message, onConfirm, onClose: null, confirmText, cancelText });
  };

  const closeModal = () => {
    const currentModal = modal;
    setModal(prev => ({ ...prev, isOpen: false }));
    // Call onClose callback after state update
    if (currentModal.onClose) {
      setTimeout(() => currentModal.onClose(), 0);
    }
  };

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

const [settings, setSettings] = useState({
  default_organisation: 'My Organisation',
  theme_variant: 'swiish',
  theme_colors: THEME_PRESETS.swiish
  });

  // Fetch CSRF token
  const fetchCsrfToken = async () => {
    try {
      const res = await fetch(`${API_ENDPOINT}/csrf-token`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setCsrfToken(data.csrfToken);
      }
    } catch (e) {
      console.error('Failed to fetch CSRF token:', e);
    }
  };

  // Helper function to make authenticated API calls
  const apiCall = async (url, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    if (csrfToken && (options.method === 'POST' || options.method === 'DELETE')) {
      headers['X-CSRF-Token'] = csrfToken;
    }

    return fetch(url, {
      ...options,
      headers,
      credentials: 'include'
    });
  };
  
  // Check setup status
  const checkSetupStatus = async () => {
    try {
      const res = await fetch(`${API_ENDPOINT}/setup/status`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setSetupStatus(data);
        return data;
      }
    } catch (e) {
      console.error('Failed to check setup status:', e);
    }
    return null;
  };

  // Router Logic - handle route changes and set view based on route
  useEffect(() => {
    const path = location.pathname;
    // Handle editor route (/people/edit/:slug) - extract slug from pathname since useParams() doesn't work at App level
    if (path.startsWith('/people/edit/')) {
      // Extract slug from pathname (remove '/people/edit/' prefix)
      const slug = path.replace('/people/edit/', '');
      // Only load if this is a different slug or we're not already in editor view
      if (currentSlug !== slug || view !== 'admin-editor') {
        setCurrentSlug(slug);
        fetchCsrfToken();
        checkAuth().then((authResult) => {
          if (authResult.isAuthenticated) {
            // After auth check, load the card data
            handleEdit(slug);
          } else {
            // If auth fails, redirect to login (explicit redirect for unauthorized access)
            navigate('/login');
          }
        }).catch(() => {
          // If auth fails, redirect to login
          navigate('/login');
        });
      }
      return;
    }
    
    // Skip public card route handling here - PublicCardRoute component handles it
    // This prevents duplicate fetches
    // Public routes: /:orgSlug/:cardSlug or /:slug (short code or legacy)
    const pathParts = path.substring(1).split('/').filter(p => p);
    const isShortCode = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
    const isOrgScoped = pathParts.length === 2 && pathParts[0] && pathParts[1];
    const isPublicRoute = isShortCode || isOrgScoped || (pathParts.length === 1 && pathParts[0] && !path.startsWith('/people') && !path.startsWith('/login') && !path.startsWith('/setup') && !path.startsWith('/settings') && !path.startsWith('/users') && !path.startsWith('/cards') && path !== '/');
    
    if (isPublicRoute) {
      // Don't interfere with public card routes - let PublicCardRoute handle it
      // Only set initial state if view is still 'loading' (first render)
      // Once PublicCardRoute takes over (view is 'public-loading' or 'public-card'), don't touch it
      if (view === 'loading') {
        setView('public-loading');
      } else if (view === 'public-loading' || view === 'public-card' || view === '404') {
        // PublicCardRoute is managing state - don't interfere
      }
      return;
    }
    
    // Set view based on route
    if (path === '/setup') {
      // Check if setup is already complete - if so, redirect to login
      fetchCsrfToken();
      checkSetupStatus().then((status) => {
        if (status && status.setupComplete && status.userCount > 0) {
          // Setup already complete, redirect to login
          navigate('/login');
        } else {
          // Setup not complete, show wizard
          setView('setup-wizard');
          document.title = "Initial Setup";
        }
      }).catch(() => {
        // If check fails, show wizard anyway
        setView('setup-wizard');
        document.title = "Initial Setup";
      });
      return;
    } else if (path === '/login') {
      // Login page - check if already authenticated
      setView('loading');
      fetchCsrfToken();
      checkAuth().then((authResult) => {
        if (authResult.isAuthenticated) {
          // If authenticated, redirect to dashboard (explicit redirect)
          navigate('/people');
        } else {
          // Not authenticated, show login page
          setView('admin-login');
          document.title = "Admin Login";
        }
      }).catch(() => {
        // Not authenticated, show login page
        setView('admin-login');
        document.title = "Admin Login";
      });
    } else if (path === '/settings') {
      setView('admin-settings');
      fetchCsrfToken();
      checkAuth().then((authResult) => {
        if (!authResult.isAuthenticated) {
          navigate('/login');
        }
      });
    } else if (path === '/users') {
      setView('user-management');
      fetchCsrfToken();
      checkAuth().then((authResult) => {
        if (!authResult.isAuthenticated) {
          navigate('/login');
        }
      });
    } else if (path === '/admin' || path === '/' || path === '/people') {
      // Check demo mode status first (will be known from setup/status response)
      fetchCsrfToken();
      checkSetupStatus().then((status) => {
        // Check if demo mode is active (from status response or isDemoMode state)
        const demoModeActive = status?.demoMode || isDemoMode;

        if (demoModeActive) {
          // Demo mode: skip setup, go directly to auth check
          if (path === '/' || path === '/admin') {
            // Redirect root/admin to /people (explicit redirect)
            navigate('/people');
            return; // Let next effect run handle /people
          }
          // Set view to loading while checking auth
          setView('loading');
          checkAuth().then((authResult) => {
            if (authResult.isAuthenticated) {
              // Demo mode: always show dashboard for demo user (owner role)
              setView('admin-dashboard');
              document.title = "Admin Dashboard";
            } else {
              // This shouldn't happen in demo mode, but fallback to login just in case
              navigate('/login');
            }
          }).catch((e) => {
            console.error('Auth check failed:', e);
            navigate('/login');
          });
          return;
        }

        // Normal mode: continue with regular auth flow
        // (status already checked above, setupComplete must be true to get here)
        if (status === null) {
          // If check failed (server not running, network error, etc.), default to setup wizard
          navigate('/setup');
          document.title = "Initial Setup";
        } else if (!status.setupComplete || status.userCount === 0) {
          // Setup not complete or no users exist, show setup wizard
          navigate('/setup');
          document.title = "Initial Setup";
        } else {
          // Setup complete, check authentication
          if (path === '/' || path === '/admin') {
            // Redirect root/admin to /people (explicit redirect)
            navigate('/people');
            return; // Let next effect run handle /people
          }
          // Set view to loading while checking auth
          setView('loading');
          checkAuth().then((authResult) => {
            if (authResult.isAuthenticated) {
              // Determine view based on role and route
              if (authResult.userData.role === 'member') {
                if (authResult.cardList.length === 0) {
                  setView('member-empty');
                } else {
                  // Navigate to first card editor (explicit navigation)
                  const firstCard = authResult.cardList[0];
                  navigate(`/people/edit/${firstCard.slug}`);
                }
              } else {
                // Owner - show dashboard
                setView('admin-dashboard');
              }
          document.title = "Admin Dashboard";
            } else {
              // Not authenticated, redirect to login (explicit redirect)
              navigate('/login');
            }
          }).catch((e) => {
            console.error('Auth check failed:', e);
            navigate('/login');
          });
        }
      }).catch((e) => {
        // If promise rejects, default to setup wizard
        console.error('Setup status check failed:', e);
        navigate('/setup');
        document.title = "Initial Setup";
      });
    }
  }, [location.pathname, navigate]);


  // checkAuth: Only updates state, never navigates
  // Returns { isAuthenticated: boolean, userData: object | null, cardList: array }
  const checkAuth = async () => {
    try {
      // Fetch CSRF token first if not already fetched
      if (!csrfToken) {
        await fetchCsrfToken();
      }
      // Fetch user info to get role
      const userRes = await apiCall(`${API_ENDPOINT}/auth/me`);
      if (userRes.ok) {
        const userData = await userRes.json();
        setUserRole(userData.role);
        setCurrentUserId(userData.id);
        setCurrentUserEmail(userData.email);
        
        // Fetch cards
        const res = await apiCall(`${API_ENDPOINT}/admin/cards`);
        if (res.ok) {
          const list = await res.json();
          setCardList(list);
          setIsAuthenticated(true);
          fetchSettings();
          
          return { isAuthenticated: true, userData, cardList: list };
        } else {
          setIsAuthenticated(false);
          setUserRole(null);
          return { isAuthenticated: false, userData: null, cardList: [] };
        }
      } else {
        setIsAuthenticated(false);
        setUserRole(null);
        return { isAuthenticated: false, userData: null, cardList: [] };
      }
    } catch (e) {
      setIsAuthenticated(false);
      setUserRole(null);
      return { isAuthenticated: false, userData: null, cardList: [] };
    }
  };

  const fetchPublicCard = async (slug) => {
    setIsPublicLoading(true);
    setView('public-loading'); // Ensure view is set to loading while fetching
    try {
      // Fetch settings first so colors are available
      await fetchPublicSettings();
      const res = await fetch(`${API_ENDPOINT}/cards/${slug}`);
      if (res.ok) {
        const json = await res.json();
        const defaultTemplate = getDefaultTemplate(settings);
        setData({ 
          ...defaultTemplate, 
          ...json, 
          links: json.links || [],
          privacy: json.privacy || defaultTemplate.privacy
        });
        setView('public-card');
        document.title = json.personal?.name ? `${json.personal.name} - Swiish Card` : "Swiish Card";
      } else {
        setError('Card not found');
        setView('404');
        document.title = "Card Not Found";
      }
    } catch (e) {
      console.error('Error fetching public card:', e);
      setError('Connection failed');
      setView('404');
      document.title = "Error Loading Card";
    } finally {
      setIsPublicLoading(false);
    }
  };

  const fetchCardByShortCode = useCallback(async (shortCode) => {
    setIsPublicLoading(true);
    try {
      // Fetch card first to get org slug, then fetch settings for that org
      const res = await fetch(`${API_ENDPOINT}/cards/short/${shortCode}`);
      if (res.ok) {
        const cardData = await res.json();
        // Fetch settings for the organization that owns this card
        const orgSlug = cardData._orgSlug || 'default';
        await fetchPublicSettings(orgSlug);
        
        const defaultTemplate = getDefaultTemplate(settings);
        const mergedData = { 
          ...defaultTemplate, 
          ...cardData, 
          links: cardData.links || [],
          privacy: cardData.privacy || defaultTemplate.privacy,
          _shortCode: cardData._shortCode // Preserve short code from backend
        };
        // Set isPublicLoading to false FIRST, then data, then view
        // This prevents renderAdminViews from showing loading when view='public-card'
        setIsPublicLoading(false);
        setData(mergedData);
        setView('public-card');
        const name = `${cardData.personal?.firstName || ''} ${cardData.personal?.lastName || ''}`.trim();
        document.title = name || 'Card';
      } else {
        setView('404');
        setError('Card not found');
        document.title = 'Card Not Found';
      }
    } catch (e) {
      console.error('[FRONTEND] Error fetching card by short code:', e);
      setView('404');
      setError('Failed to load card');
      document.title = 'Card Not Found';
    } finally {
      setIsPublicLoading(false);
    }
  }, [settings]);

  const fetchCardByOrgAndSlug = useCallback(async (orgSlug, cardSlug) => {
    setIsPublicLoading(true);
    try {
      // Fetch settings for the organization from the URL
      await fetchPublicSettings(orgSlug);
      const res = await fetch(`${API_ENDPOINT}/cards/${orgSlug}/${cardSlug}`);
      if (res.ok) {
        const cardData = await res.json();
        const defaultTemplate = getDefaultTemplate(settings);
        const mergedData = { 
          ...defaultTemplate, 
          ...cardData, 
          links: cardData.links || [],
          privacy: cardData.privacy || defaultTemplate.privacy,
          _shortCode: cardData._shortCode // Preserve short code from backend
        };
        // Set isPublicLoading to false FIRST, then data, then view
        // This prevents renderAdminViews from showing loading when view='public-card'
        setIsPublicLoading(false);
        setData(mergedData);
        setView('public-card');
        const name = `${cardData.personal?.firstName || ''} ${cardData.personal?.lastName || ''}`.trim();
        document.title = name || 'Card';
      } else {
        setView('404');
        setError('Card not found');
        document.title = 'Card Not Found';
      }
    } catch (e) {
      console.error('[FRONTEND] Error fetching card by org and slug:', e);
      setView('404');
      setError('Failed to load card');
      document.title = 'Card Not Found';
    } finally {
      setIsPublicLoading(false);
    }
  }, [settings]);

  // Helper to initialize color data for settings (shared between fetchSettings and SettingsView)
  // Note: SettingsView has its own initializeColorData function, but we need this one for fetchSettings
  const initializeColorDataForSettings = (colors) => {
    if (!colors || !Array.isArray(colors)) return [];
    return colors.map(color => {
      let hexBase, baseColor, colorType;
      
      // Determine if this is a standard color (has Tailwind gradient or baseColor) or custom hex
      const hasValidTailwindGradient = color.gradient && typeof color.gradient === 'string' && color.gradient.startsWith('from-');
      const hasHexBase = color.hexBase && typeof color.hexBase === 'string' && color.hexBase.startsWith('#');
      
      if (hasValidTailwindGradient) {
        // Convert from Tailwind gradient to hex
        const extracted = extractBaseColorFromGradient(color.gradient);
        if (extracted) {
          baseColor = extracted.baseColor;
          hexBase = getTailwindColorHex(extracted.baseColor, 600); // Always use shade 600
          colorType = 'standard';
        } else {
          // Fallback if extraction fails
          baseColor = color.baseColor || 'indigo';
          hexBase = hasHexBase ? color.hexBase : getTailwindColorHex(baseColor, 600);
          colorType = color.colorType === 'custom' ? 'custom' : 'standard';
        }
      } else if (hasHexBase) {
        // Has hexBase - determine if standard or custom
        if (color.baseColor && color.colorType !== 'custom') {
          // Standard color with hexBase
          baseColor = color.baseColor;
          hexBase = color.hexBase;
          colorType = 'standard';
        } else {
          // Custom hex color
          baseColor = null;
          hexBase = color.hexBase;
          colorType = 'custom';
        }
      } else if (color.gradientStyle) {
        // Has gradientStyle but no hexBase - extract from gradientStyle or use default
        baseColor = null;
        hexBase = '#4f46e5'; // Default
        colorType = 'custom';
      } else {
        // Fallback - treat as standard with default
        baseColor = color.baseColor || 'indigo';
        hexBase = getTailwindColorHex(baseColor, 600);
        colorType = color.colorType === 'custom' ? 'custom' : 'standard';
      }
      
      // Always auto-generate complementary secondary color
      const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
      const hexSecondary = color.hexSecondary || (complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase);
      
      // Generate all inline styles
      const gradientStyle = `linear-gradient(135deg, ${hexBase}, ${hexSecondary})`;
      const buttonStyle = hexBase;
      const linkStyle = hexBase;
      const textStyle = hexBase;
      
      // Build clean hex-only color object
      return {
        name: color.name,
        colorType: colorType,
        baseColor: baseColor, // null for custom, Tailwind name for standard
        hexBase: hexBase,
        hexSecondary: hexSecondary,
        gradientStyle: gradientStyle,
        buttonStyle: buttonStyle,
        linkStyle: linkStyle,
        textStyle: textStyle
      };
    });
  };

  const fetchSettings = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/settings`);
      if (res.ok) {
        const settingsData = await res.json();
      const merged = {
        ...settingsData,
        theme_variant: settingsData.theme_variant || 'swiish',
        theme_colors: initializeColorDataForSettings(settingsData.theme_colors || [])
      };
      setSettings(merged);
      applyThemeCssVars(merged.theme_variant);
      document.body.classList.remove('theme-swiish', 'theme-minimal', 'theme-custom');
      document.body.classList.add(`theme-${merged.theme_variant}`);
      }
    } catch (e) {
      console.error('Failed to fetch settings:', e);
    }
  };

  const fetchPublicSettings = async (orgSlug = 'default') => {
    try {
      const url = orgSlug ? `${API_ENDPOINT}/settings?orgSlug=${encodeURIComponent(orgSlug)}` : `${API_ENDPOINT}/settings`;
      const res = await fetch(url);
      if (res.ok) {
        const settingsData = await res.json();
        const mergedVariant = settingsData.theme_variant || 'swiish';
        
        // Match admin pattern: create new object from API response
        // This ensures React sees it as a new object and triggers re-renders
        const merged = {
          default_organisation: settingsData.default_organisation || 'My Organisation',
          theme_variant: mergedVariant,
          theme_colors: (settingsData.theme_colors && Array.isArray(settingsData.theme_colors)) 
            ? initializeColorDataForSettings(settingsData.theme_colors)
            : THEME_PRESETS.swiish
        };
        
        // Set state and apply theme immediately (same pattern as fetchSettings)
        setSettings(merged);
        applyThemeCssVars(mergedVariant);
        document.body.classList.remove('theme-swiish', 'theme-minimal', 'theme-custom');
        document.body.classList.add(`theme-${mergedVariant}`);
      }
    } catch (e) {
      console.error('Failed to fetch public settings:', e);
    }
  };

  // Group cards by user (userId or userEmail as fallback)
  const groupCardsByUser = (cards) => {
    const userMap = new Map();
    
    cards.forEach(card => {
      // Use userId as primary key, fallback to userEmail if userId not available
      const userKey = card.userId || card.userEmail || 'unknown';
      
      if (!userMap.has(userKey)) {
        userMap.set(userKey, {
          userId: card.userId || null,
          userEmail: card.userEmail || null,
          userRole: card.userRole || null,
          userCreatedAt: card.userCreatedAt || null,
          cards: []
        });
      }
      
      // Add card to user's cards array (even if slug is null, it represents a user without cards)
      userMap.get(userKey).cards.push(card);
    });
    
    // Convert map to array and sort by user creation date (newest first)
    return Array.from(userMap.values()).sort((a, b) => {
      if (!a.userCreatedAt && !b.userCreatedAt) return 0;
      if (!a.userCreatedAt) return 1;
      if (!b.userCreatedAt) return -1;
      return new Date(b.userCreatedAt) - new Date(a.userCreatedAt);
    });
  };

  const fetchCardList = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/cards`);
      if (res.ok) {
        const list = await res.json();
        setCardList(list);
        // Removed setView('admin-dashboard') - fetchCardList should only update data, not view
        // View should be determined by route, not by data fetching
        setIsAuthenticated(true);
        // Fetch settings when dashboard loads (only if we're actually on dashboard)
        if (location.pathname === '/people') {
        fetchSettings();
        }
      } else {
        setIsAuthenticated(false);
        // Only set view to login if we're on a protected route
        if (location.pathname !== '/login' && location.pathname !== '/setup') {
        setView('admin-login');
        }
      }
    } catch (e) {
      setIsAuthenticated(false);
      // Only set view to login if we're on a protected route
      if (location.pathname !== '/login' && location.pathname !== '/setup') {
      setView('admin-login');
      }
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch(`${API_ENDPOINT}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: email.toLowerCase().trim(), password })
      });
      if (res.ok) {
        // Token is now in httpOnly cookie, fetch CSRF token and check auth
        await fetchCsrfToken();
        const authResult = await checkAuth();
        if (authResult.isAuthenticated) {
          // Navigate to dashboard after successful login (explicit user action)
          navigate('/people');
        }
      } else {
        const errorData = await res.json().catch(() => ({}));
        setError(errorData.error || 'Invalid email or password');
      }
    } catch (e) { 
      setError('Login failed'); 
    }
  };

  const handleLogout = async () => {
    try {
      await fetch(`${API_ENDPOINT}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
    } catch (e) {
      console.error('Logout API call failed:', e);
    }
    // Force hard redirect immediately - don't set state first as it causes race conditions
    // The hard redirect will reload the page and useEffect will handle the login view
    window.location.href = '/login';
  };

  const handleSetup = async (e) => {
    e.preventDefault();
    setIsSettingUp(true);
    setError('');
    try {
      const res = await fetch(`${API_ENDPOINT}/setup/initialize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({
          organisationName: setupData.organisationName.trim(),
          adminEmail: setupData.adminEmail.toLowerCase().trim(),
          adminPassword: setupData.adminPassword
        })
      });
      if (res.ok) {
        // Setup successful, automatically log in
        setIsSuccessSetup(true);
        setTimeout(() => setIsSuccessSetup(false), 2000);
        const authResult = await checkAuth();
        if (authResult.isAuthenticated) {
          // Navigate to dashboard after successful setup (explicit user action)
          navigate('/people');
        }
      } else {
        const errorData = await res.json().catch(() => ({}));
        setError(errorData.error || 'Setup failed');
      }
    } catch (e) {
      setError('Setup failed. Please try again.');
    } finally {
      setIsSettingUp(false);
    }
  };

  const handleCreateNew = () => {
    if (userRole === 'owner') {
      // Show action selection modal for owners
      setActionSelectionModal({ isOpen: true });
    } else {
      // Members go directly to card creation (for themselves, no userId needed)
      setCreateCardModal({ isOpen: true, slug: '', userId: null });
    }
  };

  const handleCreateCardConfirm = () => {
    const slug = createCardModal.slug.toLowerCase().trim().replace(/[^a-z0-9-]/g, '');
    if (!slug) {
      showAlert('Please enter a valid user URL (e.g., "sarah")', 'error', 'Invalid User URL');
      return;
    }
    if (slug.length < 1) {
      showAlert('User URL must be at least 1 character long', 'error', 'Invalid User URL');
      return;
    }
    // Prevent duplicate user URLs for the same user
    // Flatten all cards from grouped structure to check for duplicates
    const allCards = cardList.filter(c => c.slug === slug);
    if (allCards.length > 0) {
      showAlert(`A card with user URL "${slug}" already exists. Please choose another user URL.`, 'error', 'User URL already exists');
      return;
    }
    // Store userId for this new card if provided
    if (createCardModal.userId) {
      setTargetUserIdForNewCard(createCardModal.userId);
    }
    setCreateCardModal({ isOpen: false, slug: '', userId: null });
    setCurrentSlug(slug);
    setData(getDefaultTemplate(settings)); 
    setView('admin-editor');
    // Navigate to editor route, just like handleEdit does
    navigate(`/people/edit/${slug}`);
  };

  const handleCreateCardCancel = () => {
    setCreateCardModal({ isOpen: false, slug: '' });
  };

  const handleCreateUser = async () => {
    if (!newUser.email || !newUser.password) {
      if (showAlert) showAlert('Email and password are required', 'error');
      return;
    }

    if (newUser.password.length < 8) {
      if (showAlert) showAlert('Password must be at least 8 characters long', 'error');
      return;
    }

    setIsSavingUser(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users`, {
        method: 'POST',
        body: JSON.stringify(newUser)
      });
      
      if (res.ok) {
        setIsSuccessCreateUser(true);
        setTimeout(() => setIsSuccessCreateUser(false), 2000);
        setShowCreateUserModal(false);
        setNewUser({ email: '', password: '', role: 'member' });
        checkAuth(); // Refresh card list
      } else {
        // Try to parse error response
        let errorMessage = 'Failed to create user';
        try {
          const errorData = await res.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
          console.error('User creation failed:', {
            status: res.status,
            statusText: res.statusText,
            error: errorData
          });
        } catch (parseError) {
          // Response is not JSON, use status text
          console.error('User creation failed - non-JSON response:', {
            status: res.status,
            statusText: res.statusText
          });
          errorMessage = `Failed to create user: ${res.status} ${res.statusText}`;
        }
        if (showAlert) showAlert(errorMessage, 'error');
        // Don't close modal on error - let user fix and retry
      }
    } catch (e) {
      console.error('Error creating user:', e);
      const errorMessage = e.message || 'Error creating user. Please try again.';
      if (showAlert) showAlert(errorMessage, 'error');
    } finally {
      setIsSavingUser(false);
    }
  };

  const handleSendInvitation = async () => {
    if (!newInvitation.email) {
      if (showAlert) showAlert('Email is required', 'error');
      return;
    }

    setIsSavingUser(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/invitations`, {
        method: 'POST',
        body: JSON.stringify(newInvitation)
      });
      if (res.ok) {
        setIsSuccessInvite(true);
        setTimeout(() => setIsSuccessInvite(false), 2000);
        setShowInviteModal(false);
        setNewInvitation({ email: '', role: 'member' });
      } else {
        const errorData = await res.json().catch(() => ({}));
        if (showAlert) showAlert(errorData.error || 'Failed to send invitation', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error sending invitation', 'error');
    } finally {
      setIsSavingUser(false);
    }
  };

  const handleUpdateRole = async (userId, newRole) => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ role: newRole })
      });
      if (res.ok) {
        if (showAlert) showAlert('User role updated successfully', 'success');
        checkAuth(); // Refresh card list
        setEditingUserId(null);
      } else {
        const errorData = await res.json().catch(() => ({}));
        if (showAlert) showAlert(errorData.error || 'Failed to update role', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error updating role', 'error');
    }
  };

  const handleRemoveUser = async (userId, userEmail) => {
    if (showConfirm) {
      showConfirm(
        `Are you sure you want to remove ${userEmail} from the organisation?`,
        async () => {
          try {
            const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
              method: 'DELETE'
            });
            if (res.ok) {
              if (showAlert) showAlert('User removed successfully', 'success');
              checkAuth(); // Refresh card list
            } else {
              const errorData = await res.json().catch(() => ({}));
              if (showAlert) showAlert(errorData.error || 'Failed to remove user', 'error');
            }
          } catch (e) {
            if (showAlert) showAlert('Error removing user', 'error');
          }
        },
        'Remove User',
        'Remove',
        'Cancel'
      );
    }
  };

  const handleEdit = async (slug) => {
    const res = await fetch(`${API_ENDPOINT}/cards/${slug}`, {
      credentials: 'include'
    });
    if (res.ok) {
      const json = await res.json();
      const defaultTemplate = getDefaultTemplate(settings);
      setData({ 
        ...defaultTemplate, 
        ...json,
        // Enforce default_organisation from organization settings
        personal: {
          ...defaultTemplate.personal,
          ...json.personal,
          company: settings?.default_organisation || json.personal?.company || defaultTemplate.personal.company
        },
        links: json.links || [],
        privacy: json.privacy || defaultTemplate.privacy
      });
      setCurrentSlug(slug);
      setView('admin-editor');
      // Navigate to editor route only if not already there
      if (location.pathname !== `/people/edit/${slug}`) {
        navigate(`/people/edit/${slug}`);
      }
    }
  };

  const handleDelete = async (slug) => {
    showConfirm(
      `Are you sure you want to delete ${slug}?`,
      async () => {
        const res = await apiCall(`${API_ENDPOINT}/cards/${slug}`, {
          method: 'DELETE'
        });
        if (res.ok) {
          showAlert('Card deleted successfully', 'success', '', () => {
            fetchCardList();
          });
        } else {
          showAlert('Failed to delete card', 'error');
        }
      },
      'Delete Card',
      'Delete',
      'Cancel'
    );
  };

  const handleSave = async () => {
    const performSave = async () => {
      setIsSaving(true);
      const startTime = Date.now();
      try {
        // Include userId in request body if creating card for another user
        const body = { ...data };
        if (targetUserIdForNewCard) {
          body.userId = targetUserIdForNewCard;
        }

        const res = await apiCall(`${API_ENDPOINT}/cards/${currentSlug}`, {
          method: 'POST',
          body: JSON.stringify(body)
        });

        // Ensure at least 500ms has passed
        const elapsedTime = Date.now() - startTime;
        if (elapsedTime < 500) {
          await new Promise(resolve => setTimeout(resolve, 500 - elapsedTime));
        }

        if (res.ok) {
          // Clear targetUserIdForNewCard after successful save
          setTargetUserIdForNewCard(null);
          setIsSuccess(true);
          fetchCardList();
          setTimeout(() => setIsSuccess(false), 2000);
        } else {
          showAlert('Save failed', 'error');
        }
      } finally {
        setIsSaving(false);
      }
    };

    const email = (data.contact?.email || '').trim().toLowerCase();
    if (email && cardList.length > 0) {
      // Only check against actual cards (those with slugs) - this excludes user entries without cards
      // Also exclude the current card being edited
      const duplicates = cardList.filter(c => 
        c.slug && // Must be an actual card
        c.email && // Must have a contact email
        c.email === email && // Must match the email being saved
        c.slug !== currentSlug // Must not be the current card being edited
      );
      if (duplicates.length > 0) {
        showConfirm(
          `Another card already uses this email address (${email}). Would you like to save anyway?`,
          performSave,
          'Email already in use',
          'Save anyway',
          'Cancel'
        );
        return;
      }
    }

    await performSave();
  };

  // Always use Routes for proper URL handling
  // Admin routes must be defined before /:slug to prevent matching
  // All admin views are consolidated here to avoid duplication
  const renderAdminViews = () => (
    <>
      {view === 'loading' && (
        <>
          <div className="h-screen flex items-center justify-center text-text-muted-subtle dark:text-text-muted-dark bg-main dark:bg-main-dark bg-main-texture">Loading...</div>
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === '404' && (
        <>
          <div className="h-screen flex flex-col items-center justify-center bg-main dark:bg-main-dark bg-main-texture">
            <h1 className="text-4xl font-bold text-text-primary dark:text-text-primary-dark mb-2">404</h1>
            <p className="text-text-muted dark:text-text-muted-dark">Card not found.</p>
          </div>
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === 'setup-wizard' && (
        <>
          <div className="min-h-screen bg-surface dark:bg-main-dark flex items-center justify-center p-4">
            <div className="bg-card dark:bg-card-dark max-w-md w-full rounded-page shadow-xl p-8">
              <div className="text-center mb-8">
                <div className="w-16 h-16 bg-indigo-100 dark:bg-indigo-900/30 rounded-full flex items-center justify-center mx-auto mb-4 text-indigo-600 dark:text-indigo-400"><Settings className="w-8 h-8" /></div>
                <h1 className="text-2xl font-bold text-text-primary dark:text-text-primary-dark">Initial Setup</h1>
                <p className="text-sm text-text-muted dark:text-text-muted-dark mt-2">Configure your organisation and create the first admin user</p>
              </div>
              <form onSubmit={handleSetup} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2">Organisation Name</label>
                  <input 
                    type="text" 
                    value={setupData.organisationName} 
                    onChange={e => setSetupData({ ...setupData, organisationName: e.target.value })} 
                    placeholder="My Organization" 
                    className="w-full px-5 py-3 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark" 
                    required 
                    autoFocus 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2">Admin Email</label>
                  <input 
                    type="email" 
                    value={setupData.adminEmail} 
                    onChange={e => setSetupData({ ...setupData, adminEmail: e.target.value })} 
                    placeholder="admin@example.com" 
                    className="w-full px-5 py-3 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark" 
                    required 
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2">Admin Password</label>
                  <input 
                    type="password" 
                    value={setupData.adminPassword} 
                    onChange={e => setSetupData({ ...setupData, adminPassword: e.target.value })} 
                    placeholder="Minimum 8 characters" 
                    className="w-full px-5 py-3 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark" 
                    required 
                    minLength={8}
                  />
                  <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">Password must be at least 8 characters long</p>
                </div>
                {error && <div className="flex items-center gap-2 text-error-text dark:text-error-text-dark text-sm">{error}</div>}
                <button 
                  type="submit" 
                  disabled={isSettingUp}
                  className="w-full py-3.5 rounded-full bg-action dark:bg-action-dark text-white font-bold hover:bg-action-hover dark:hover:bg-action-hover-dark transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isSettingUp ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : isSuccessSetup ? (
                    <Check className="w-4 h-4 text-green-500" />
                  ) : (
                    <Save className="w-4 h-4" />
                  )}
                  {isSettingUp ? 'Setting up...' : 'Complete Setup'}
                </button>
              </form>
              <div className="text-center mt-auto pt-8 pb-0 group relative z-10" style={{ boxSizing: 'content-box' }}>
                <div className="flex justify-center">
                  <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
                  <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
                </div>
              </div>
            </div>
          </div>
          <VersionBadge />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === 'admin-login' && (
        <>
          <div className="min-h-screen bg-surface dark:bg-main-dark flex items-center justify-center p-4">
            <div className="bg-card dark:bg-card-dark max-w-sm w-full rounded-page shadow-xl p-8">
              <div className="text-center mb-8">
                <div className="w-16 h-16 bg-indigo-100 dark:bg-indigo-900/30 rounded-full flex items-center justify-center mx-auto mb-4 text-indigo-600 dark:text-indigo-400"><Lock className="w-8 h-8" /></div>
                <h1 className="text-2xl font-bold text-text-primary dark:text-text-primary-dark">Login</h1>
              </div>
              <form onSubmit={handleLogin} className="space-y-4">
                <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" className="w-full px-5 py-3 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark" autoFocus />
                <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" className="w-full px-5 py-3 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark" />
                {error && <div className="flex items-center gap-2 text-error-text dark:text-error-text-dark text-sm">{error}</div>}
                <button type="submit" className="w-full py-3.5 rounded-full bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark font-bold hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark transition-colors">Login</button>
              </form>
            <div className="text-center mt-8 group relative z-10">
              <div className="flex justify-center">
                <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
                <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
              </div>
            </div>
            </div>
          </div>
          <VersionBadge />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === 'admin-dashboard' && (
        <>
          <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture p-6 md:p-12 flex flex-col">
          <div className="max-w-6xl mx-auto flex-1 w-full">
            {/* UPDATED HEADER: flex-wrap + gap adjustments for mobile */}
            <div className="flex flex-wrap justify-between items-center mb-8 gap-4 relative z-10">
               <div>
                 <h1 className="text-2xl md:text-3xl font-bold text-text-primary dark:text-text-primary-dark">People</h1>
                 <p className="text-sm md:text-base text-text-muted dark:text-text-muted-dark">Manage your people</p>
               </div>
               <div className="flex flex-wrap gap-2 md:gap-3 w-full md:w-auto">
                 <button onClick={toggleDarkMode} className="px-3 py-2 md:px-4 md:py-3 rounded-full font-medium text-text-muted dark:text-text-muted-dark bg-card dark:bg-card-dark border border-border dark:border-border-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors whitespace-nowrap flex items-center gap-2 text-sm md:text-base">
                   {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                 </button>
                 <button onClick={handleLogout} className="px-3 py-2 md:px-4 md:py-3 rounded-full font-medium text-text-muted dark:text-text-muted-dark bg-card dark:bg-card-dark border border-border dark:border-border-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors whitespace-nowrap text-sm md:text-base">Logout</button>
                 {userRole === 'owner' && (
                   <button onClick={() => navigate('/settings')} className="px-3 py-2 md:px-4 md:py-3 rounded-full font-medium text-text-secondary dark:text-text-secondary-dark bg-card dark:bg-card-dark border border-border dark:border-border-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors whitespace-nowrap flex items-center gap-2 text-sm md:text-base">
                     <Settings className="w-4 h-4" /> <span className="hidden sm:inline">Organisation</span><span className="sm:hidden">Org</span>
                   </button>
                 )}
                 {userRole === 'owner' && (
                   <button onClick={() => navigate('/users')} className="px-3 py-2 md:px-4 md:py-3 rounded-full font-medium text-text-secondary dark:text-text-secondary-dark bg-card dark:bg-card-dark border border-border dark:border-border-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors whitespace-nowrap flex items-center gap-2 text-sm md:text-base">
                     <Users className="w-4 h-4" /> Users
                   </button>
                 )}
                 <button onClick={handleCreateNew} className="bg-action dark:bg-action-dark text-white px-4 py-2 md:px-6 md:py-3 rounded-full font-bold flex items-center gap-2 hover:bg-action-hover dark:hover:bg-action-hover-dark transition-all whitespace-nowrap text-sm md:text-base">
                   <Plus className="w-4 h-4 md:w-5 md:h-5" /> New Person
                 </button>
               </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {groupCardsByUser(cardList).map(user => {
                // Filter out entries without slugs (these represent users without cards)
                const userCards = user.cards.filter(c => c.slug);
                const userKey = user.userId || user.userEmail || 'unknown';
                
                return (
                  <div key={userKey} className="bg-card dark:bg-card-dark rounded-card shadow-sm border border-border-subtle dark:border-border-dark hover:shadow-md transition-shadow flex flex-col p-[15px]">
                    {/* User Info Box (top) - only shown for owners */}
                    {userRole === 'owner' && user.userEmail && (
                      <div className="w-full mb-[15px]">
                        <div className="bg-surface dark:bg-surface-dark/50 rounded-t-container rounded-b-badge p-5 text-xs border border-border dark:border-border-dark min-h-[130px]">
                          <div className="text-text-secondary dark:text-text-muted-dark truncate mb-2 font-medium">{user.userEmail}</div>
                          <div className="flex items-center justify-between mb-2">
                            <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium ${
                              user.userRole === 'owner' 
                                ? 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300' 
                                : 'bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark'
                            }`}>
                              {user.userRole === 'owner' ? 'Owner' : 'Member'}
                            </span>
                            {user.userCreatedAt && (
                              <span className="text-text-muted dark:text-text-muted-dark text-[10px]">
                                {new Date(user.userCreatedAt).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                          {user.userId && user.userId !== currentUserId && (
                            <div className="flex items-center gap-2 mt-2 pt-2 border-t border-border dark:border-border-dark">
                              {editingUserId === user.userId ? (
                                <div className="flex items-center gap-2 w-full">
                                  <select
                                    value={user.userRole}
                                    onChange={(e) => handleUpdateRole(user.userId, e.target.value)}
                                    className="flex-1 px-2 py-1 text-[10px] rounded border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark"
                                  >
                                    <option value="member">Member</option>
                                    <option value="owner">Owner</option>
                                  </select>
                                  <button
                                    onClick={() => setEditingUserId(null)}
                                    className="px-2 py-1 text-[10px] bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded hover:bg-surface dark:hover:bg-surface-dark"
                                  >
                                    Cancel
                                  </button>
                                </div>
                              ) : (
                                <>
                                  <button
                                    onClick={() => setEditingUserId(user.userId)}
                                    className="flex-1 px-2 py-1 text-[10px] bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded hover:bg-surface dark:hover:bg-surface-dark flex items-center justify-center gap-1"
                                  >
                                    <Edit3 className="w-3 h-3" /> Role
                                  </button>
                                  <button
                                    onClick={() => handleRemoveUser(user.userId, user.userEmail)}
                                    className="flex-1 px-2 py-1 text-[10px] bg-error-bg dark:bg-error-bg-dark text-error dark:text-error-text-dark rounded hover:bg-error-bg dark:hover:bg-error-bg-dark flex items-center justify-center gap-1"
                                  >
                                    <Trash2 className="w-3 h-3" /> Remove
                                  </button>
                                </>
                              )}
                            </div>
                          )}
                          {user.userId === currentUserId && (
                            <div className="text-[10px] text-text-muted dark:text-text-muted-dark italic mt-2 pt-2 border-t border-border dark:border-border-dark">
                              Cannot modify yourself
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {/* Cards for this user - stacked vertically */}
                    <div className="w-full space-y-[15px]">
                      {userCards.length > 0 ? (
                        <>
                          {userCards.map(card => (
                            <div key={card.slug} className="bg-surface dark:bg-surface-dark/50 rounded-badge p-5 border border-border dark:border-border-dark" style={{ aspectRatio: '1.586 / 1' }}>
                              <div className="w-full h-full flex flex-col">
                                <div className="flex-1 flex flex-row items-start gap-3 mb-3 relative">
                                  <div className="w-20 h-20 rounded-full bg-surface dark:bg-surface-dark overflow-hidden border-thick border-border-subtle dark:border-border-dark flex-shrink-0">
                                    {card.avatar ? <img src={card.avatar} className="w-full h-full object-cover" alt="avatar" /> : <User className="w-full h-full p-5 text-text-muted-subtle dark:text-text-muted-dark" />}
                                  </div>
                                  <button onClick={(e) => { e.stopPropagation(); handleDelete(card.slug); }} className="absolute top-0 right-0 p-2 text-text-muted-subtle dark:text-text-muted-dark hover:text-error-text dark:hover:text-error-text-dark hover:bg-error-bg dark:hover:bg-error-bg-dark rounded-full transition-colors">
                                    <Trash2 className="w-4 h-4" />
                                  </button>
                                  <div className="flex-1 flex flex-col text-left min-w-0">
                                    <h3 className="font-bold text-text-primary dark:text-text-primary-dark text-base mb-0.5 truncate">{card.name}</h3>
                                    {card.title && <p className="text-text-muted dark:text-text-muted-dark text-xs mb-1 truncate">{card.title}</p>}
                                    <div className="space-y-0.5">
                                      {card.shortCode && (
                                        <div className="text-[10px] text-text-muted-subtle dark:text-text-muted-dark font-mono truncate" title="Short Code URL">
                                          <span className="text-text-muted-subtle dark:text-text-muted-dark">Short:</span> /{card.shortCode}
                                        </div>
                                      )}
                                      {card.orgSlug && card.slug ? (
                                        <div className="text-[10px] text-text-muted-subtle dark:text-text-muted-dark font-mono truncate" title="Org-scoped URL">
                                          <span className="text-text-muted-subtle dark:text-text-muted-dark">URL:</span> /{card.orgSlug}/{card.slug}
                                        </div>
                                      ) : card.slug ? (
                                        <div className="text-[10px] text-text-muted-subtle dark:text-text-muted-dark font-mono truncate" title="Legacy URL">
                                          <span className="text-text-muted-subtle dark:text-text-muted-dark">URL:</span> /{card.slug}
                                        </div>
                                      ) : null}
                                    </div>
                                  </div>
                                </div>
                                <div className="flex items-center justify-center gap-2 w-full mt-auto">
                                  <a 
                                    href={card.shortCode ? `/${card.shortCode}` : (card.orgSlug && card.slug ? `/${card.orgSlug}/${card.slug}` : `/${card.slug}`)} 
                                    target="_blank" 
                                    rel="noreferrer" 
                                    className="flex-1 py-2 text-xs font-medium text-confirm-text dark:text-confirm-text-dark bg-confirm dark:bg-confirm-dark rounded-button hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark flex items-center justify-center gap-1"
                                  >
                                    <ExternalLink className="w-3 h-3"/> View
                                  </a>
                                  <button onClick={() => handleEdit(card.slug)} className="flex-1 py-2 text-xs font-medium text-confirm-text dark:text-confirm-text-dark bg-confirm dark:bg-confirm-dark rounded-button hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark flex items-center justify-center gap-1"><Edit3 className="w-3 h-3"/> Edit</button>
                                </div>
                              </div>
                            </div>
                          ))}
                          {/* Create Card button at bottom of card list */}
                          <div className="bg-surface dark:bg-surface-dark/30 rounded-t-badge rounded-b-container border-thick border-dashed border-border dark:border-border-dark p-[15px] flex items-center justify-center">
                            <button onClick={() => setCreateCardModal({ isOpen: true, slug: '', userId: user.userId || user.userEmail })} className="px-4 py-2 text-sm font-medium text-white bg-action dark:bg-action-dark rounded-button hover:bg-action-hover dark:hover:bg-action-hover-dark flex items-center justify-center gap-2"><Plus className="w-4 h-4"/> Create Card</button>
                          </div>
                        </>
                      ) : (
                        /* No cards - show Create Card button in place */
                        <div className="bg-surface dark:bg-surface-dark/50 rounded-badge p-5 border border-border dark:border-border-dark" style={{ aspectRatio: '1.586 / 1' }}>
                          <div className="w-full h-full bg-surface dark:bg-surface-dark/30 rounded-badge border-thick border-dashed border-border dark:border-border-dark flex flex-col items-center justify-center">
                            <button onClick={() => setCreateCardModal({ isOpen: true, slug: '', userId: user.userId || user.userEmail })} className="px-4 py-3 text-sm font-medium text-white bg-action dark:bg-action-dark rounded-button hover:bg-action-hover dark:hover:bg-action-hover-dark flex items-center justify-center gap-2"><Plus className="w-4 h-4"/> Create Card</button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
              {cardList.length === 0 && (
                 <div className="col-span-full py-20 text-center text-text-muted-subtle dark:text-text-muted-dark bg-card dark:bg-card-dark rounded-card border-thick border-dashed border-border dark:border-border-dark">
                   No people yet. Click "New Person" to start.
                 </div>
              )}
          </div>
          </div>
          </div>
          <div className="fixed bottom-4 right-4 z-10 text-center group">
            <div className="flex justify-center">
              <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
              <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
            </div>
          </div>
          {/* Modals */}
          {actionSelectionModal.isOpen && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
              <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
                <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">What would you like to do?</h3>
                <div className="space-y-3">
                  <button
                    onClick={() => {
                      setActionSelectionModal({ isOpen: false });
                      setShowInviteModal(true);
                    }}
                    className="w-full px-4 py-3 bg-action dark:bg-action-dark text-white rounded-button font-medium hover:bg-action-hover dark:hover:bg-action-hover-dark flex items-center justify-center gap-2"
                  >
                    <Users className="w-4 h-4" /> Invite User
                  </button>
                  <button
                    onClick={() => {
                      setActionSelectionModal({ isOpen: false });
                      setShowCreateUserModal(true);
                    }}
                    className="w-full px-4 py-3 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-button font-medium hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark flex items-center justify-center gap-2"
                  >
                    <User className="w-4 h-4" /> Create User
                  </button>
                </div>
                <button
                  onClick={() => setActionSelectionModal({ isOpen: false })}
                  className="w-full mt-4 px-4 py-2 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
          {/* Invite User Modal */}
          {showInviteModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
              <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
                <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Invite User</h3>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Email</label>
                    <input
                      type="email"
                      value={newInvitation.email}
                      onChange={(e) => setNewInvitation({ ...newInvitation, email: e.target.value })}
                      className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                      placeholder="user@example.com"
                    />
                    <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">An invitation email will be sent to this address</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Role</label>
                    <select
                      value={newInvitation.role}
                      onChange={(e) => setNewInvitation({ ...newInvitation, role: e.target.value })}
                      className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                    >
                      <option value="member">Member</option>
                      <option value="owner">Owner</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button
                    onClick={() => {
                      setShowInviteModal(false);
                      setNewInvitation({ email: '', role: 'member' });
                    }}
                    className="flex-1 px-4 py-2.5 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSendInvitation}
                    disabled={isSavingUser}
                    className="flex-1 px-4 py-2.5 bg-action dark:bg-action-dark text-white rounded-button font-bold hover:bg-action-hover dark:hover:bg-action-hover-dark disabled:opacity-50"
                  >
                    {isSavingUser ? 'Sending...' : 'Send Invitation'}
                  </button>
                </div>
              </div>
            </div>
          )}
          {/* Create User Modal */}
          {showCreateUserModal && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
              <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
                <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Create New User</h3>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Email</label>
                    <input
                      type="email"
                      value={newUser.email}
                      onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                      className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                      placeholder="user@example.com"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Password</label>
                    <input
                      type="password"
                      value={newUser.password}
                      onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                      className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                      placeholder="Minimum 8 characters"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Role</label>
                    <select
                      value={newUser.role}
                      onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                      className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                    >
                      <option value="member">Member</option>
                      <option value="owner">Owner</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button
                    onClick={() => {
                      setShowCreateUserModal(false);
                      setNewUser({ email: '', password: '', role: 'member' });
                    }}
                    className="flex-1 px-4 py-2.5 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateUser}
                    disabled={isSavingUser}
                    className="flex-1 px-4 py-2.5 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-button font-bold hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark disabled:opacity-50"
                  >
                    {isSavingUser ? 'Creating...' : 'Create User'}
                  </button>
                </div>
              </div>
            </div>
          )}
          <VersionBadge />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
          <Modal
            isOpen={createCardModal.isOpen}
            onClose={handleCreateCardCancel}
            type="info"
            title="Create New Card"
            message="Enter a user URL for the new card (e.g., 'sarah'):"
            inputLabel="User URL"
            inputPlaceholder="sarah"
            inputValue={createCardModal.slug}
            onInputChange={(value) => setCreateCardModal(prev => ({ ...prev, slug: value }))}
            onConfirm={handleCreateCardConfirm}
            confirmText="Create"
            cancelText="Cancel"
          />
        </>
      )}
      {view === 'member-empty' && (
        <>
          <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex items-center justify-center p-6">
            <div className="bg-card dark:bg-card-dark rounded-card shadow-lg max-w-md w-full p-8 text-center">
              <div className="w-16 h-16 bg-indigo-100 dark:bg-indigo-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
                <User className="w-8 h-8 text-indigo-600 dark:text-indigo-400" />
              </div>
              <h2 className="text-xl font-bold text-text-primary dark:text-text-primary-dark mb-2">You don't have a card yet</h2>
              <p className="text-text-secondary dark:text-text-muted-dark mb-6">Create your first card to get started.</p>
              <button
                onClick={() => setCreateCardModal({ isOpen: true, slug: '' })}
                className="w-full px-4 py-3 bg-action dark:bg-action-dark text-white rounded-button font-bold hover:bg-action-hover dark:hover:bg-action-hover-dark flex items-center justify-center gap-2"
              >
                <Plus className="w-4 h-4" /> Create Card
              </button>
              <button
                onClick={handleLogout}
                className="w-full mt-3 px-4 py-2 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
              >
                Logout
              </button>
            </div>
          </div>
          <Modal 
            isOpen={createCardModal.isOpen} 
            onClose={handleCreateCardCancel} 
            type="info" 
            title="Create New Card" 
            message="Enter a user URL for the new card (e.g., 'sarah'):"
            inputLabel="User URL"
            inputPlaceholder="sarah"
            inputValue={createCardModal.slug}
            onInputChange={(value) => setCreateCardModal(prev => ({ ...prev, slug: value }))}
            onConfirm={handleCreateCardConfirm}
            confirmText="Create"
            cancelText="Cancel"
          />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === 'admin-editor' && (
        <>
          <EditorView 
            data={data} 
            setData={setData} 
            onBack={() => { navigate('/people'); fetchCardList(); }} 
            onSave={handleSave}
            slug={currentSlug}
            settings={settings}
            csrfToken={csrfToken}
            showAlert={showAlert}
            darkMode={darkMode}
            toggleDarkMode={toggleDarkMode}
            isSaving={isSaving}
            isSuccess={isSuccess}
          />
          <VersionBadge />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === 'admin-settings' && (
        <>
          <SettingsView
            settings={settings}
            setSettings={setSettings}
            apiCall={apiCall}
            onBack={() => { navigate('/people'); fetchCardList(); }}
            onSave={async () => {
              await fetchSettings();
              fetchCardList();
              }}
            showAlert={showAlert}
            showConfirm={showConfirm}
          />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
      {view === 'user-management' && (
        <>
          <UserManagementView
            apiCall={apiCall}
            userRole={userRole}
            onBack={() => { navigate('/people'); fetchCardList(); }}
            showAlert={showAlert}
            showConfirm={showConfirm}
          />
          <Modal isOpen={modal.isOpen} onClose={closeModal} type={modal.type} title={modal.title} message={modal.message} onConfirm={modal.onConfirm} confirmText={modal.confirmText} cancelText={modal.cancelText} />
        </>
      )}
    </>
  );

  return (
    <>
      <DemoModeBanner />
      <Routes>
        {/* Admin routes - must come before public routes to prevent matching */}
        <Route path="/login" element={renderAdminViews()} />
        <Route path="/people/edit/:slug" element={renderAdminViews()} />
        <Route path="/people" element={renderAdminViews()} />
        <Route path="/settings" element={renderAdminViews()} />
        <Route path="/users" element={renderAdminViews()} />
        <Route path="/cards" element={renderAdminViews()} />
        <Route path="/" element={renderAdminViews()} />
        {/* Public card routes - org-scoped must come before single slug */}
        <Route path="/:orgSlug/:cardSlug" element={
          <PublicCardRoute 
            view={view}
            isPublicLoading={isPublicLoading}
            error={error}
            data={data}
            settings={settings}
            darkMode={darkMode}
            toggleDarkMode={toggleDarkMode}
            showAlert={showAlert}
            fetchCardByOrgAndSlug={fetchCardByOrgAndSlug}
            fetchCardByShortCode={fetchCardByShortCode}
            fetchPublicCard={fetchPublicCard}
          />
        } />
        {/* Public card route - matches short code or legacy slug */}
        <Route path="/:slug" element={
          <PublicCardRoute 
            view={view}
            isPublicLoading={isPublicLoading}
            error={error}
            data={data}
            settings={settings}
            darkMode={darkMode}
            toggleDarkMode={toggleDarkMode}
            showAlert={showAlert}
            fetchCardByOrgAndSlug={fetchCardByOrgAndSlug}
            fetchCardByShortCode={fetchCardByShortCode}
            fetchPublicCard={fetchPublicCard}
          />
        } />
        {/* Catch-all for other routes */}
        <Route path="*" element={renderAdminViews()} />
      </Routes>
    </>
  );
}

function PublicCardRoute({ view, isPublicLoading, error, data, settings, darkMode, toggleDarkMode, showAlert, fetchCardByOrgAndSlug, fetchCardByShortCode, fetchPublicCard }) {
  const params = useParams();
  const location = useLocation();
  
  
  // Track the last fetched pathname to prevent duplicate fetches
  const lastFetchedPathRef = useRef(null);
  
  // Apply app theme variant class to body for CSS overrides (swiish|minimal|custom)
  // This ensures the theme is applied to public cards the same way as admin views
  useEffect(() => {
    const variant = settings?.theme_variant || 'swiish';
    document.body.classList.remove('theme-swiish', 'theme-minimal', 'theme-custom');
    document.body.classList.add(`theme-${variant}`);
    applyThemeCssVars(variant);
  }, [settings]);
  
  // Fetch the card when the route changes
  useEffect(() => {
    const path = location.pathname;
    
    // Single guard: skip if we've already fetched for this exact pathname
    if (lastFetchedPathRef.current === path) {
      return;
    }
    
    // Parse route to determine fetch strategy
    const pathParts = path.substring(1).split('/').filter(p => p);
    const isShortCode = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
    const isOrgScoped = pathParts.length === 2 && pathParts[0] && pathParts[1];
    const isLegacy = pathParts.length === 1 && !isShortCode;
    
    // Mark this path as being fetched BEFORE calling fetch (prevents race conditions)
    lastFetchedPathRef.current = path;
    
    // Fetch based on route type
    if (isShortCode && fetchCardByShortCode) {
      fetchCardByShortCode(pathParts[0]);
    } else if (isOrgScoped && fetchCardByOrgAndSlug) {
      fetchCardByOrgAndSlug(pathParts[0], pathParts[1]);
    } else if (isLegacy && fetchPublicCard) {
      fetchPublicCard(pathParts[0]);
    } else {
      console.error('[PublicCardRoute] No valid fetch strategy for path:', path);
      // Reset ref if we can't fetch (allows retry on next render if functions become available)
      lastFetchedPathRef.current = null;
    }
  }, [location.pathname, fetchCardByOrgAndSlug, fetchCardByShortCode, fetchPublicCard]);
  
  // Show loading state while fetching card
  const pathParts = location.pathname.substring(1).split('/').filter(p => p);
  const hasPublicRouteParams = params.slug || params.cardSlug || params.orgSlug || pathParts.length > 0;
  
  if (isPublicLoading || ((view === 'loading' || view === 'public-loading') && hasPublicRouteParams)) {
    return (
      <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex justify-center items-center">
        <div className="text-text-muted-subtle dark:text-text-muted-dark">Loading...</div>
      </div>
    );
  }
  
  // Show 404 if card not found
  if (view === '404') {
    return (
      <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex justify-center items-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-text-primary dark:text-text-primary-dark mb-2">Card Not Found</h1>
          <p className="text-text-secondary dark:text-text-muted-dark">{error || 'The card you are looking for does not exist.'}</p>
        </div>
      </div>
    );
  }
  
  // Show card when loaded
  if (view === 'public-card' && data && data.personal) {
  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex justify-center items-start lg:items-center p-0 lg:p-8">
      <div className="w-full max-w-md bg-card dark:bg-card-dark min-h-screen lg:min-h-0 lg:h-auto lg:rounded-page shadow-2xl overflow-hidden relative animate-in fade-in duration-500 flex flex-col">
        <div className="flex-1">
          <CardDisplay
            data={data}
            settings={settings}
            darkMode={darkMode}
            toggleDarkMode={toggleDarkMode}
            showAlert={showAlert}
          />
        </div>
      </div>
      </div>
    );
  }
  
  // Default: show loading (shouldn't reach here, but safety net)
  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex justify_center items-center">
      <div className="text-text-muted-subtle dark:text-text-muted-dark">Loading...</div>
    </div>
  );
}

function CardDisplay({ data, settings, darkMode, toggleDarkMode, showAlert }) {
  const { personal = {}, contact = {}, social = {}, images = {}, theme = { color: 'indigo' }, links = [], privacy = {} } = data;
  const themeColor = settings?.theme_colors?.find(c => c.name === theme.color);
  const [showQR, setShowQR] = useState(false);
  const [qrMode, setQrMode] = useState(() => {
    if (typeof navigator !== 'undefined') {
      return navigator.onLine ? 'simple' : 'rich';
    }
    return 'simple';
  });
  const [qrSimpleDataUrl, setQrSimpleDataUrl] = useState('');
  const [qrRichDataUrl, setQrRichDataUrl] = useState('');
  const [offlineQrPayload, setOfflineQrPayload] = useState(null);
  const [isOnline, setIsOnline] = useState(
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );
  const [qrError, setQrError] = useState(null);
  const [contactRevealed, setContactRevealed] = useState(false);
  const [showSendOptions, setShowSendOptions] = useState(false);
  const [deferredPrompt, setDeferredPrompt] = useState(null);
  const [isPwaInstalled, setIsPwaInstalled] = useState(false);
  
  // Lead capture deep links, using the card owner's contact details
  const ownerPhone = contact.phone || '';
  const ownerEmail = contact.email || '';
  // Extract digits only from E.164 format (e.g., +447779331447 -> 447779331447)
  // This works for both E.164 (+44...) and legacy formats
  const ownerPhoneDigits = ownerPhone.replace(/\D/g, '');

  const whatsappLink = ownerPhoneDigits && ownerPhoneDigits.length >= 8
    ? `https://wa.me/${ownerPhoneDigits}?text=${encodeURIComponent(
        'Hi, we met via your Swiish card. My name is ... and my number/email is ...'
      )}`
    : null;

  const emailLink = ownerEmail
    ? `mailto:${ownerEmail}?subject=${encodeURIComponent(
        'My details from Swiish'
      )}&body=${encodeURIComponent(
        'Hi, we met via your Swiish card.\nMy name is ...\nMy phone number is ...\nMy email address is ...'
      )}`
    : null;

  const dropCallLink = ownerPhone ? `tel:${ownerPhone}` : null;
  
  // Helper functions for obfuscation
  const obfuscateContact = (value) => {
    if (!value) return '';
    return btoa(value);
  };
  
  const deobfuscateContact = (obfuscated) => {
    if (!obfuscated) return '';
    try {
      return atob(obfuscated);
    } catch (e) {
      return '';
    }
  };
  
  // Apply app theme variant class to body for CSS overrides (swiish|minimal|custom)
  // This ensures the theme is applied when CardDisplay renders (both in editor preview and public view)
  useEffect(() => {
    const variant = settings?.theme_variant || 'swiish';
    document.body.classList.remove('theme-swiish', 'theme-minimal', 'theme-custom');
    document.body.classList.add(`theme-${variant}`);
    applyThemeCssVars(variant);
  }, [settings]);
  
  // UPDATED: Set Title
  useEffect(() => {
    const firstName = sanitizeText(personal.firstName || '');
    const lastName = sanitizeText(personal.lastName || '');
    if (firstName || lastName) {
      document.title = `${firstName} ${lastName}`;
    }
  }, [personal]);

  // Dynamic per-card manifest link (per-card app name & start_url)
  // Note: The manifest link is updated synchronously in index.html before React loads
  // This useEffect is just a backup to ensure it's correct after navigation
  useEffect(() => {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;
    const path = window.location.pathname || '';
    const slug = path.replace(/^\//, '').split('/')[0];
    if (!slug || slug === 'admin') return;

    const head = document.head;
    let link = document.querySelector('link[rel="manifest"]');
    const dynamicHref = `/manifest/${slug}.json`;

    if (!link) {
      link = document.createElement('link');
      link.setAttribute('rel', 'manifest');
      head.appendChild(link);
    }

    if (link.getAttribute('href') !== dynamicHref) {
      link.setAttribute('href', dynamicHref);
    }
  }, []);

  // Handle PWA install prompt (keep button visible until actually installed)
  useEffect(() => {
    const handleBeforeInstall = (e) => {
      e.preventDefault();
      setDeferredPrompt(e);
    };

    const handleAppInstalled = () => {
      setIsPwaInstalled(true);
      setDeferredPrompt(null);
    };

    const checkStandalone = () => {
      const isStandalone =
        window.matchMedia('(display-mode: standalone)').matches ||
        window.navigator.standalone === true;
      if (isStandalone) {
        setIsPwaInstalled(true);
      }
    };

    checkStandalone();

    // Set up event listeners
    window.addEventListener('beforeinstallprompt', handleBeforeInstall);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstall);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  const shouldShowInstallButton = !isPwaInstalled;

  // Track online/offline status for UI
  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Handle robots meta tag
  useEffect(() => {
    if (privacy.blockRobots) {
      let metaRobots = document.querySelector('meta[name="robots"]');
      if (!metaRobots) {
        metaRobots = document.createElement('meta');
        metaRobots.setAttribute('name', 'robots');
        document.head.appendChild(metaRobots);
      }
      metaRobots.setAttribute('content', 'noindex, nofollow');
    } else {
      const metaRobots = document.querySelector('meta[name="robots"]');
      if (metaRobots) {
        metaRobots.remove();
      }
    }
    
    // Cleanup on unmount
    return () => {
      const metaRobots = document.querySelector('meta[name="robots"]');
      if (metaRobots) {
        metaRobots.remove();
      }
    };
  }, [privacy.blockRobots]);

  // Fetch QR code when modal opens; also cache rich payload for offline use
  useEffect(() => {
    if (!showQR) return;

    setQrError(null);

    // Get short code from data (if available) or extract from URL
    const pathParts = typeof window !== 'undefined' ? window.location.pathname.substring(1).split('/').filter(p => p) : [];
    const isShortCodeRoute = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
    const shortCode = data._shortCode || (isShortCodeRoute ? pathParts[0] : null);
    
    // For QR generation, always use short code if available, otherwise fallback to slug
    const qrIdentifier = shortCode || (pathParts.length > 0 ? pathParts[pathParts.length - 1] : '');
    
    const payload = buildQrPayload(shortCode, { personal, contact, social, images, theme });
    // Always cache latest rich payload for offline use
    saveQrPayloadToStorage(payload);

    // Online check – if offline, try to use cached payload instead of hitting API
    const isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;

    if (!isOnline) {
      // In offline mode, only rich mode can leverage cached payload;
      // simple (link-only) QR is effectively online-only unless previously loaded.
      if (qrMode === 'rich') {
        const cached = loadQrPayloadFromStorage();
        if (cached) {
          setOfflineQrPayload(cached);
        }
      }
      return;
    }

    if (qrMode === 'simple' && !qrSimpleDataUrl) {
      fetch(`${API_ENDPOINT}/qr/${qrIdentifier}`, {
        method: 'GET',
        credentials: 'include'
      })
        .then(res => {
          if (!res.ok) {
            throw new Error(`QR request failed: ${res.status}`);
          }
          return res.json();
        })
        .then(data => {
          if (data?.qrCode) {
            setQrSimpleDataUrl(data.qrCode);
          }
        })
        .catch(err => {
          console.error('Failed to fetch simple QR code:', err);
          setQrError('Unable to load link-only QR right now. Please try again in a moment.');
        });
    } else if (qrMode === 'rich' && !qrRichDataUrl) {
      fetch(`${API_ENDPOINT}/qr/${qrIdentifier}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ payload })
      })
        .then(res => {
          if (!res.ok) {
            throw new Error(`QR request failed: ${res.status}`);
          }
          return res.json();
        })
        .then(data => {
          if (data?.qrCode) {
            setQrRichDataUrl(data.qrCode);
          }
          saveQrPayloadToStorage(payload);
          setOfflineQrPayload(payload);
        })
        .catch(err => {
          console.error('Failed to fetch rich QR code:', err);
          const cached = loadQrPayloadFromStorage();
          if (cached) {
            setOfflineQrPayload(cached);
          }
          setQrError('Unable to load full-details QR right now. Your last saved details are still available offline.');
        });
    }
  }, [showQR, qrMode, qrSimpleDataUrl, qrRichDataUrl, personal, contact, social, images, theme, data]);

  const generateVCard = () => {
    const firstName = sanitizeText(personal.firstName || '');
    const lastName = sanitizeText(personal.lastName || '');
    const company = sanitizeText(personal.company || '');
    const title = sanitizeText(personal.title || '');
    const phone = sanitizeText(contact.phone || '');
    const email = sanitizeText(contact.email || '');
    const website = sanitizeText(contact.website || '');
    const bio = sanitizeText(personal.bio || '');
    
    const vcard = `BEGIN:VCARD
VERSION:3.0
FN:${firstName} ${lastName}
N:${lastName};${firstName};;;
ORG:${company}
TITLE:${title}
TEL;TYPE=CELL:${phone}
EMAIL;TYPE=WORK:${email}
URL:${website}
NOTE:${bio}
END:VCARD`;
    const blob = new Blob([vcard], { type: 'text/vcard' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${firstName}_${lastName}.vcf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const currentQrDataUrl = qrMode === 'simple' ? qrSimpleDataUrl : qrRichDataUrl;

  // Extract short code for display
  const pathParts = typeof window !== 'undefined' ? window.location.pathname.substring(1).split('/').filter(p => p) : [];
  const isShortCodeRoute = pathParts.length === 1 && /^[a-zA-Z0-9]{7}$/.test(pathParts[0]);
  const shortCode = data._shortCode || (isShortCodeRoute ? pathParts[0] : null);
  const shortUrl = shortCode ? `${window.location.origin}/${shortCode}` : '';
  const cardName = `${personal.firstName || ''} ${personal.lastName || ''}`.trim();
  const company = personal.company || '';

  // If QR is shown, render only the QR view (full screen, independent of card)
  if (showQR) {
    return (
      <div className="fixed inset-0 bg-card dark:bg-card-dark flex flex-col text-center overflow-hidden lg:rounded-[22px] z-50 min-h-screen lg:min-h-0 lg:h-auto">
        {/* QR Code section at top */}
        <div className="flex flex-col items-center justify-start pt-8 px-4 pb-8 lg:pt-8 lg:flex-shrink-0">
          <div className="w-[90%]">
            <div className="w-full bg-input-bg dark:bg-input-bg-dark p-3 rounded-input border-thick border-border-subtle dark:border-border-dark flex items-center justify-center overflow-hidden">
              {currentQrDataUrl ? (
                <img src={currentQrDataUrl} className="w-full aspect-square mix-blend-multiply dark:mix-blend-normal" alt="QR code" />
              ) : qrMode === 'rich' && offlineQrPayload ? (
                <div className="w-full aspect-square flex flex-col items-center justify-center text-text-muted-subtle dark:text-text-secondary-dark text-xs space-y-1">
                  <span>{isOnline ? 'Saved details' : 'Offline mode'}</span>
                  <span className="text-[10px] opacity-80 px-1">
                    This code includes your saved Swiish details and a link to your card when scanned with an online device.
                  </span>
                </div>
              ) : (!isOnline && qrMode === 'simple' && !qrSimpleDataUrl) ? (
                <div className="w-full aspect-square flex flex-col items-center justify-center text-text-muted-subtle dark:text-text-secondary-dark text-xs text-center space-y-1">
                  <span>Link-only QR is available when you&apos;re online.</span>
                  <span className="text-[10px] opacity-80 px-1">
                    Switch to \"Full details\" to use your saved offline code.
                  </span>
                </div>
              ) : (
                <div className="w-full aspect-square flex items-center justify-center text-text-muted-subtle dark:text-text-muted-dark text-xs text-center">
                  {isOnline
                    ? (qrError || 'Loading your QR code...')
                    : 'Connect once to generate and save your QR code for offline use.'}
                </div>
              )}
            </div>
          </div>

          {/* Card information display */}
          <div className="mt-6 space-y-2 px-4">
            {cardName && (
              <h2 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">{cardName}</h2>
            )}
            {company && (
              <div className="text-text-muted dark:text-text-muted-dark text-sm">{company}</div>
            )}
            {shortUrl && (
              <div className="text-text-muted-subtle dark:text-text-secondary-dark text-xs font-mono break-all">{shortUrl}</div>
            )}
          </div>

          {/* Offline note */}
          {!isOnline && offlineQrPayload && (
            <p className="text-xs text-text-muted dark:text-text-muted-dark mt-4 px-4">
              Using last saved QR details (offline). The code includes your contact info and a link to your Swiish card.
            </p>
          )}
        </div>

        {/* Controls and logo section at bottom */}
        <div className="mt-auto pb-4 px-4 space-y-3 lg:pb-4 lg:pt-4 lg:flex-shrink-0">
          {/* Toggle buttons */}
          <div className="flex w-full items-center justify-center gap-1 bg-surface dark:bg-surface-dark rounded-full p-1 text-[11px] max-w-md mx-auto">
            <button
              type="button"
              onClick={() => setQrMode('simple')}
              className={`flex-1 px-2.5 py-1 rounded-full font-medium transition-colors ${
                qrMode === 'simple'
                  ? 'bg-card dark:bg-main-dark text-text-primary dark:text-text-primary-dark shadow-sm'
                  : 'text-text-muted dark:text-text-secondary-dark'
              }`}
            >
              Link only
            </button>
            <button
              type="button"
              onClick={() => setQrMode('rich')}
              className={`flex-1 px-2.5 py-1 rounded-full font-medium transition-colors ${
                qrMode === 'rich'
                  ? 'bg-card dark:bg-main-dark text-text-primary dark:text-text-primary-dark shadow-sm'
                  : 'text-text-muted dark:text-text-secondary-dark'
              }`}
            >
              Full details
            </button>
          </div>

          {/* Close button */}
          <button onClick={() => setShowQR(false)} className="w-full max-w-md mx-auto py-3 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-primary-dark font-bold rounded-input hover:bg-surface dark:hover:bg-surface-dark text-sm transition-colors">Close</button>

          {/* Swiish logo */}
          <div className="bg-card dark:bg-card-dark text-center space-y-2 mt-[24px] mb-[12px]">
            <div className="flex justify-center py-4">
              <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
              <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Otherwise, render the normal card view
  return (
    <div className={`flex flex-col h-full bg-card dark:bg-card-dark`}>
      <div className="h-44 w-full relative bg-surface dark:bg-surface-dark">
        {images.banner ? (
          <img src={images.banner} className="w-full h-full object-cover" alt="banner" />
        ) : (
          (() => {
            const gradientStyle = getThemeGradient(theme.color, settings);
            return <div className="w-full h-full opacity-90" style={{ background: gradientStyle }} />;
          })()
        )}
        <div className="absolute top-4 right-4 flex gap-2">
          <button onClick={toggleDarkMode} className="bg-white/30 dark:bg-black/30 backdrop-blur-md p-2.5 rounded-full text-white hover:bg-white/40 dark:hover:bg-black/40 transition-all border border-white/20 dark:border-white/10 shadow-sm">
            {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
          </button>
          <button onClick={() => setShowQR(true)} className="bg-white/30 dark:bg-black/30 backdrop-blur-md p-2.5 rounded-full text-white hover:bg-white/40 dark:hover:bg-black/40 transition-all border border-white/20 dark:border-white/10 shadow-sm" aria-label="Show QR code" title="Show QR code">
            <Share2 className="w-5 h-5" />
          </button>
          {shouldShowInstallButton && (
            <button
              onClick={async () => {
                if (deferredPrompt) {
                  try {
                    await deferredPrompt.prompt();
                    const { outcome } = await deferredPrompt.userChoice;
                    if (outcome === 'accepted') {
                      setIsPwaInstalled(true);
                    }
                  } catch (e) {
                    console.error('Install prompt failed:', e);
                    if (typeof showAlert === 'function') {
                      showAlert(
                        'Install prompt failed. Please use your browser menu to install: Chrome/Edge (three dots menu > Install app), Firefox (menu > Install), or Safari (Share > Add to Home Screen).',
                        'error',
                        'Install Failed'
                      );
                    }
                  } finally {
                    setDeferredPrompt(null);
                  }
                } else {
                  // Check if app is already installed
                  const isStandalone = window.matchMedia('(display-mode: standalone)').matches ||
                                      window.navigator.standalone === true;
                  
                  if (isStandalone) {
                    if (typeof showAlert === 'function') {
                      showAlert(
                        'This app is already installed on your device.',
                        'info',
                        'Already Installed'
                      );
                    }
                    setIsPwaInstalled(true);
                  } else {
                    // Provide manual installation instructions
                    const userAgent = navigator.userAgent.toLowerCase();
                    let instructions = 'To install this app:\n\n';
                    
                    if (userAgent.includes('chrome') || userAgent.includes('edge')) {
                      instructions += 'Chrome/Edge: Click the three dots menu (⋮) in the address bar, then select "Install app" or "Add to Home Screen".';
                    } else if (userAgent.includes('firefox')) {
                      instructions += 'Firefox: Click the menu button, then select "Install" or "Add to Home Screen".';
                    } else if (userAgent.includes('safari')) {
                      instructions += 'Safari (iOS): Tap the Share button, then "Add to Home Screen".';
                    } else {
                      instructions += 'Open your browser menu and look for "Install app" or "Add to Home Screen" option.';
                    }
                    
                    instructions += '\n\nNote: The install button may not be available if the app doesn\'t meet PWA requirements (service worker, valid manifest, etc.).';
                    
                    if (typeof showAlert === 'function') {
                      showAlert(
                        instructions,
                        'info',
                        'Install Swiish'
                      );
                    } else {
                      // Fallback if showAlert is not available
                      alert(instructions);
                    }
                  }
                }
              }}
              className="bg-white/30 dark:bg-black/30 backdrop-blur-md p-2.5 rounded-full text-white hover:bg-white/40 dark:hover:bg-black/40 transition-all border border-white/20 dark:border-white/10 shadow-sm"
              aria-label="Install app for offline access"
              title="Install app for offline access"
            >
              <Download className="w-5 h-5" />
            </button>
          )}
          {!isOnline && offlineQrPayload && (
            <span className="hidden xs:inline-flex items-center px-3 py-1 rounded-full text-[10px] font-semibold bg-amber-500/80 text-white shadow-sm">
              Offline QR ready
            </span>
          )}
        </div>
      </div>

      <div className="px-6 pb-6 -mt-16 relative flex-1 flex flex-col min-h-0">
        <div className="w-32 h-32 min-h-[8rem] flex-shrink-0 rounded-full border-avatar border-white dark:border-card-dark shadow-xl overflow-hidden bg-card dark:bg-card-dark relative mb-4">
          {images.avatar ? <img src={images.avatar} className="w-full h-full object-cover" alt="avatar" /> : <div className="w-full h-full bg-surface dark:bg-surface-dark flex items-center justify-center text-text-muted-subtle dark:text-text-muted-dark"><User className="w-12 h-12" /></div>}
        </div>

        <div className="space-y-1 mb-8">
          <h1 className="text-3xl font-bold text-text-primary dark:text-text-primary-dark tracking-tight">{sanitizeText(`${personal.firstName || ''} ${personal.lastName || ''}`).trim() || 'Untitled'}</h1>
          {(() => {
            const color = settings?.theme_colors?.find(c => c.name === theme.color);
            const title = sanitizeText(personal.title || '');
            if (color?.textStyle) {
              return <div className="text-lg font-medium" style={{ color: color.textStyle }}>{title}</div>;
            }
            return <div className="text-lg font-medium" style={{ color: getTextColor(theme.color, settings) }}>{title}</div>;
          })()}
          <div className="flex items-center text-text-muted dark:text-text-muted-dark text-sm gap-2"><Briefcase className="w-4 h-4" /><span>{sanitizeText(personal.company || '')}</span></div>
          {personal.location && <div className="flex items-center text-text-muted-subtle dark:text-text-muted-dark text-sm gap-2 mt-1"><MapPin className="w-4 h-4" /><span>{sanitizeText(personal.location)}</span></div>}
        </div>

        {personal.bio && <div className="mb-8"><p className="text-text-secondary dark:text-text-secondary-dark leading-relaxed text-sm" dangerouslySetInnerHTML={{ __html: sanitizeHTML(personal.bio) }}></p></div>}

        <div className="grid grid-cols-2 gap-3 mb-8">
          {(() => {
            const requireInteraction = privacy.requireInteraction ?? true;
            const shouldShowVCF = !requireInteraction || contactRevealed;
            
            // Only show VCF button if interaction is not required OR contact has been revealed
            if (shouldShowVCF) {
              const color = settings?.theme_colors?.find(c => c.name === theme.color);
              if (color?.buttonStyle) {
                const hoverColor = darkenHex(color.buttonStyle, 10);
                return (
                  <button 
                    onClick={generateVCard} 
                    className="col-span-2 flex items-center justify-center gap-2 py-3.5 rounded-full font-bold text-white shadow-lg transition-all active:scale-[0.98]"
                    style={{ backgroundColor: color.buttonStyle }}
                    onMouseEnter={(e) => {
                      e.target.style.backgroundColor = hoverColor;
                    }}
                    onMouseLeave={(e) => {
                      e.target.style.backgroundColor = color.buttonStyle;
                    }}
                  >
                    <Save className="w-5 h-5" /> Save Contact
                  </button>
                );
              }
              return (
                <button 
                  onClick={generateVCard} 
                  className="col-span-2 flex items-center justify-center gap-2 py-3.5 rounded-full font-bold text-white shadow-lg transition-transform active:scale-[0.98]"
                  style={{ backgroundColor: getButtonColor(theme.color, settings) }}
                >
                  <Save className="w-5 h-5" /> Save Contact
                </button>
              );
            }
            return null;
          })()}
          {(() => {
            const requireInteraction = privacy.requireInteraction ?? true;
            const useObfuscation = privacy.clientSideObfuscation ?? false;
            const hasEmail = contact.email;
            const hasPhone = contact.phone;
            
            // If interaction required and not yet revealed, show reveal button
            if (requireInteraction && !contactRevealed && (hasEmail || hasPhone)) {
              return (
                <button
                  onClick={() => setContactRevealed(true)}
                  className="col-span-2 flex items-center justify-center gap-2 py-3.5 rounded-full font-semibold bg-surface dark:bg-surface-dark text-text-primary dark:text-text-primary-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors border border-border dark:border-border-dark"
                >
                  <Eye className="w-5 h-5" /> See my details
                </button>
              );
            }
            
            // Get actual contact values
            const emailValue = hasEmail ? contact.email : '';
            const phoneValue = hasPhone ? contact.phone : '';
            
            // If obfuscation is enabled, store obfuscated values in data attributes
            const emailData = useObfuscation && emailValue ? obfuscateContact(emailValue) : '';
            const phoneData = useObfuscation && phoneValue ? obfuscateContact(phoneValue) : '';
            
            return (
              <>
                {hasEmail && (
                  <a
                    href={useObfuscation ? '#' : `mailto:${emailValue}`}
                    data-email={useObfuscation ? emailData : undefined}
                    onClick={(e) => {
                      if (useObfuscation) {
                        e.preventDefault();
                        const actualEmail = deobfuscateContact(e.currentTarget.dataset.email);
                        window.location.href = `mailto:${actualEmail}`;
                      }
                    }}
                    className="flex items-center justify-center gap-2 py-3.5 rounded-full font-semibold bg-surface dark:bg-surface-dark text-text-primary dark:text-text-primary-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors border border-border dark:border-border-dark"
                  >
                    <Mail className="w-5 h-5" /> Email
                  </a>
                )}
                {hasPhone && (
                  <a
                    href={useObfuscation ? '#' : `tel:${phoneValue}`}
                    data-phone={useObfuscation ? phoneData : undefined}
                    onClick={(e) => {
                      if (useObfuscation) {
                        e.preventDefault();
                        const actualPhone = deobfuscateContact(e.currentTarget.dataset.phone);
                        window.location.href = `tel:${actualPhone}`;
                      }
                    }}
                    className="flex items-center justify-center gap-2 py-3.5 rounded-full font-semibold bg-surface dark:bg-surface-dark text-text-primary dark:text-text-primary-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors border border-border dark:border-border-dark"
                  >
                    <Phone className="w-5 h-5" /> Call
                  </a>
                )}
              </>
            );
          })()}
        </div>

        {/* Send your details CTA */}
        <div className="mb-8">
          <button
            type="button"
            onClick={() => setShowSendOptions(open => !open)}
            className="w-full flex items-center justify-center gap-2 py-3.5 rounded-full font-semibold bg-confirm text-confirm-text dark:bg-confirm-dark dark:text-confirm-text-dark hover:opacity-90 transition-colors shadow-lg active:scale-[0.98]"
          >
            <MessageCircle className="w-5 h-5" />
            {showSendOptions ? 'Hide send options' : 'Send your details'}
          </button>

          {showSendOptions && (
            <div className="mt-3 space-y-2 rounded-card border border-border dark:border-border-dark bg-surface/60 dark:bg-card-dark/60 p-3 text-left">
              {whatsappLink && (
                <a
                  href={whatsappLink}
                  target="_blank"
                  rel="noreferrer"
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-full font-semibold bg-success dark:bg-success-dark text-white hover:bg-success-hover dark:hover:bg-success-hover-dark transition-colors"
                >
                  <MessageCircle className="w-5 h-5" />
                  WhatsApp me your number
                </a>
              )}

              {emailLink && (
                <a
                  href={emailLink}
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-full font-semibold bg-surface dark:bg-surface-dark text-text-primary dark:text-text-primary-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors border border-border dark:border-border-dark"
                >
                  <Mail className="w-5 h-5" />
                  Email me your details
                </a>
              )}

              {dropCallLink && (
                <a
                  href={dropCallLink}
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-full font-semibold bg-surface dark:bg-surface-dark text-text-primary dark:text-text-primary-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors border border-border dark:border-border-dark"
                >
                  <Phone className="w-5 h-5" />
                  Drop call me your number
                </a>
              )}

              <p className="mt-1 text-[11px] text-text-muted dark:text-text-muted-dark text-center">
                Only shared with me, never sold.
              </p>
            </div>
          )}
        </div>

        {links.length > 0 && (
          <div className="flex flex-col gap-3 mb-8">
            {links.map(link => {
              const color = settings?.theme_colors?.find(c => c.name === theme.color);
              if (color?.linkStyle) {
                return (
                  <a 
                    key={link.id}
                    href={link.url} 
                    target="_blank" 
                    rel="noreferrer"
                    className="flex items-center p-4 rounded-input border transition-all active:scale-[0.99]"
                    style={{ 
                      color: color.linkStyle, 
                      backgroundColor: color.linkStyle + '15',
                      borderColor: color.linkStyle + '30'
                    }}
                    onMouseEnter={(e) => {
                      e.target.style.backgroundColor = color.linkStyle + '25';
                      const iconContainer = e.target.querySelector('.link-icon-container');
                      if (iconContainer) {
                        iconContainer.style.transform = 'scale(1.1)';
                      }
                    }}
                    onMouseLeave={(e) => {
                      e.target.style.backgroundColor = color.linkStyle + '15';
                      const iconContainer = e.target.querySelector('.link-icon-container');
                      if (iconContainer) {
                        iconContainer.style.transform = 'scale(1)';
                      }
                    }}
                  >
                    <div className="mr-4 p-2 bg-input-bg dark:bg-input-bg-dark rounded-container shadow-sm transition-transform link-icon-container">
                      {React.createElement(ICON_MAP[link.icon] || LinkIcon, { className: "w-5 h-5 text-text-secondary dark:text-text-secondary-dark" })}
                    </div>
                    <span className="font-semibold text-sm flex-1">{sanitizeText(link.title || '')}</span>
                    <ExternalLink className="w-4 h-4 opacity-50" />
                  </a>
                );
              }
              return (
                <a 
                  key={link.id} 
                  href={link.url} 
                  target="_blank" 
                  rel="noreferrer"
                  className="flex items-center p-4 rounded-input border transition-all active:scale-[0.99] dark:border-border-dark"
                  style={{ color: getLinkColor(theme.color, settings) }}
                  onMouseEnter={(e) => {
                    const iconContainer = e.target.querySelector('.link-icon-container');
                    if (iconContainer) {
                      iconContainer.style.transform = 'scale(1.1)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    const iconContainer = e.target.querySelector('.link-icon-container');
                    if (iconContainer) {
                      iconContainer.style.transform = 'scale(1)';
                    }
                  }}
                >
                  <div className="mr-4 p-2 bg-input-bg dark:bg-input-bg-dark rounded-container shadow-sm transition-transform link-icon-container">
                    {React.createElement(ICON_MAP[link.icon] || LinkIcon, { className: "w-5 h-5 text-text-secondary dark:text-text-secondary-dark" })}
                  </div>
                  <span className="font-semibold text-sm flex-1">{link.title}</span>
                  <ExternalLink className="w-4 h-4 opacity-50" />
                </a>
              );
            })}
          </div>
        )}

        <div className="grid grid-cols-4 gap-3 mb-8">
           <SocialIcon url={contact.website} icon={Globe} label="Web" themeColor={themeColor} />
           <SocialIcon url={social.linkedin} icon={Linkedin} label="LinkedIn" themeColor={themeColor} />
           <SocialIcon url={social.twitter} icon={Twitter} label="X" themeColor={themeColor} />
           <SocialIcon url={social.instagram} icon={Instagram} label="Insta" themeColor={themeColor} />
           <SocialIcon url={social.github} icon={Github} label="Git" themeColor={themeColor} />
        </div>

        {/* Swiish logo */}
        <div className="bg-card dark:bg-card-dark pb-4 text-center space-y-2 mt-auto lg:pb-4">
          <div className="flex justify-center">
            <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
            <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
          </div>
        </div>
      </div>
    </div>
  );
}

function SortableLinkItem({ link, children }) {
  const { attributes, listeners, setNodeRef, transform, transition } = useSortable({ id: link.id });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition
  };
  return children({ setNodeRef, style, attributes, listeners });
}

function EditorView({ data, setData, onBack, onSave, slug, settings, csrfToken, showAlert, darkMode, toggleDarkMode, isSaving, isSuccess }) {
  const [activeTab, setActiveTab] = useState('details');
  const [isUploading, setIsUploading] = useState(false);
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: { distance: 5 }
    })
  );
  
  const handleInputChange = (section, field, value) => {
    setData(prev => ({ ...prev, [section]: { ...prev[section], [field]: value } }));
  };

  const handleImageUpload = async (type, e) => {
    const file = e.target.files[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_ENDPOINT}/upload`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'X-CSRF-Token': csrfToken
        },
        body: formData
      });
      
      if (res.ok) {
        const { url } = await res.json();
        setData(prev => ({ ...prev, images: { ...prev.images, [type]: url } }));
      } else {
        if (showAlert) showAlert('Upload failed', 'error');
      }
    } catch (error) {
      if (showAlert) showAlert('Upload error', 'error');
    } finally {
      setIsUploading(false);
    }
  };

  const addLink = () => {
    const newLink = { id: Date.now(), title: '', url: '', icon: 'link' };
    setData(prev => ({ ...prev, links: [...prev.links, newLink] }));
  };
  const removeLink = (id) => {
    setData(prev => ({ ...prev, links: prev.links.filter(l => l.id !== id) }));
  };
  const updateLink = (id, field, value) => {
    setData(prev => ({ ...prev, links: prev.links.map(l => l.id === id ? { ...l, [field]: value } : l) }));
  };

  const reorderLinks = (oldIndex, newIndex) => {
    if (oldIndex === newIndex) return;
    setData(prev => ({ ...prev, links: arrayMove(prev.links, oldIndex, newIndex) }));
  };

  const moveLinkUp = (index) => {
    if (index <= 0) return;
    reorderLinks(index, index - 1);
  };

  const moveLinkDown = (index) => {
    if (index >= data.links.length - 1) return;
    reorderLinks(index, index + 1);
  };

  const handleDragEnd = (event) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    const oldIndex = data.links.findIndex(link => link.id === active.id);
    const newIndex = data.links.findIndex(link => link.id === over.id);
    if (oldIndex === -1 || newIndex === -1) return;
    reorderLinks(oldIndex, newIndex);
  };

  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex flex-col lg:flex-row">
      <div className="w-full lg:w-1/2 bg-card dark:bg-card-dark border-r border-border dark:border-border-dark h-auto lg:h-screen overflow-y-auto flex flex-col">
        <div className="p-6 border-b border-border-subtle dark:border-border-dark flex items-center justify-between bg-card dark:bg-card-dark sticky top-0 z-10">
          <div className="flex items-center gap-4">
             <button onClick={onBack} className="p-2 hover:bg-surface dark:hover:bg-surface-dark rounded-full text-text-muted dark:text-text-muted-dark"><ArrowLeft className="w-5 h-5"/></button>
             <div>
               <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">Editing: {slug}</h1>
             </div>
          </div>
          <button
            onClick={onSave}
            disabled={isSaving}
            className="px-5 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold flex items-center gap-2 hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark transition-colors disabled:opacity-50"
          >
            {isSaving ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : isSuccess ? (
              <Check className="w-4 h-4 text-green-500" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            Save
          </button>
        </div>

        <div className="flex-1 p-6 space-y-8">
           <div className="flex p-1 bg-surface dark:bg-surface-dark rounded-input mb-6">
              {['details', 'links', 'images', 'style', 'privacy'].map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)} className={`flex-1 py-2 text-sm font-medium rounded-button capitalize transition-all ${activeTab === tab ? 'bg-card dark:bg-surface-dark shadow text-text-primary dark:text-text-primary-dark' : 'text-text-muted dark:text-text-muted-dark hover:text-text-primary dark:hover:text-text-primary-dark'}`}>{tab}</button>
              ))}
           </div>

           {activeTab === 'details' && (
             <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Input label="First Name" value={data.personal.firstName} onChange={v => handleInputChange('personal', 'firstName', v)} />
                  <Input label="Last Name" value={data.personal.lastName} onChange={v => handleInputChange('personal', 'lastName', v)} />
                  <Input label="Job Title" value={data.personal.title} onChange={v => handleInputChange('personal', 'title', v)} />
                  <div className="space-y-1">
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">Organisation</label>
                    <div className="relative">
                      <input 
                        type="text" 
                        value={settings?.default_organisation || data.personal.company || ''} 
                        disabled
                        className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-surface dark:bg-surface-dark text-text-secondary dark:text-text-muted-dark cursor-not-allowed" 
                        placeholder="Organisation Name"
                      />
                      <div className="absolute inset-0 flex items-center justify-end pr-3 pointer-events-none">
                        <Lock className="w-4 h-4 text-text-muted-subtle dark:text-text-muted-dark" />
                      </div>
                    </div>
                    <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">Organisation name is set by your organisation</p>
                  </div>
                </div>
                <Input label="Location" value={data.personal.location} onChange={v => handleInputChange('personal', 'location', v)} />
                <TextArea label="Bio" value={data.personal.bio} onChange={v => handleInputChange('personal', 'bio', v)} />
                <div className="h-px bg-surface dark:bg-surface-dark" />
                <div className="space-y-4">
                  <Input icon={Mail} placeholder="Email" value={data.contact.email} onChange={v => handleInputChange('contact', 'email', v)} type="email" />
                  <div className="space-y-1">
                    <PhoneInput
                      international
                      defaultCountry="GB"
                      value={data.contact.phone || ''}
                      onChange={(value) => handleInputChange('contact', 'phone', value || '')}
                      placeholder="Phone"
                      flags={flags}
                    />
                  </div>
                  <Input icon={Globe} placeholder="Website" value={data.contact.website} onChange={v => handleInputChange('contact', 'website', v)} type="url" />
                  <Input icon={Linkedin} placeholder="LinkedIn" value={data.social.linkedin} onChange={v => handleInputChange('social', 'linkedin', v)} type="url" />
                  <Input icon={Twitter} placeholder="Twitter / X" value={data.social.twitter} onChange={v => handleInputChange('social', 'twitter', v)} type="url" />
                  <Input icon={Instagram} placeholder="Instagram" value={data.social.instagram} onChange={v => handleInputChange('social', 'instagram', v)} type="url" />
                  <Input icon={Github} placeholder="Github" value={data.social.github} onChange={v => handleInputChange('social', 'github', v)} type="url" />
                </div>
             </div>
           )}

           {activeTab === 'links' && (
             <div className="space-y-6">
                <div className="flex justify-between items-center">
                    <h3 className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">Custom Links</h3>
                    {settings?.allow_links_customisation !== false ? (
                      <button onClick={addLink} className="text-sm font-bold text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 flex items-center gap-1"><Plus className="w-4 h-4" /> Add Link</button>
                    ) : (
                      <div className="flex items-center gap-2 text-text-muted dark:text-text-muted-dark">
                        <Lock className="w-4 h-4" />
                        <span className="text-sm">Locked</span>
                      </div>
                    )}
                </div>
                {settings?.allow_links_customisation === false ? (
                  <LockedOption message="Your organisation has disabled custom links. Contact your administrator to enable this feature.">
                    <div className="space-y-4">
                      {data.links.map((link, index) => (
                        <div key={link.id} className="bg-surface dark:bg-surface-dark p-4 rounded-input border border-border dark:border-border-dark">
                          <div className="grid gap-3">
                            <div className="flex gap-3 items-center">
                              <div className="w-10 h-10 rounded-container bg-card dark:bg-surface-dark border border-border dark:border-border-dark flex items-center justify-center shrink-0">
                                {React.createElement(ICON_MAP[link.icon] || LinkIcon, { className: "w-5 h-5 text-text-secondary dark:text-text-secondary-dark" })}
                              </div>
                              <input type="text" value={link.title} disabled className="flex-1 bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-muted dark:text-text-muted-dark rounded-input px-3 py-2 text-sm cursor-not-allowed" />
                            </div>
                            <input type="text" value={link.url} disabled className="w-full bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-muted dark:text-text-muted-dark rounded-input px-3 py-2 text-sm cursor-not-allowed" />
                          </div>
                        </div>
                      ))}
                      {data.links.length === 0 && (
                        <div className="text-center py-8 text-text-muted-subtle dark:text-text-muted-dark text-sm border-thick border-dashed border-border dark:border-border-dark rounded-input">
                          No custom links yet.
                        </div>
                      )}
                    </div>
                  </LockedOption>
                ) : (
                <div className="space-y-4">
                    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                      <SortableContext items={data.links.map(link => link.id)} strategy={verticalListSortingStrategy}>
                        {data.links.map((link, index) => (
                          <SortableLinkItem key={link.id} link={link}>
                            {({ setNodeRef, style, attributes, listeners }) => (
                              <div
                                ref={setNodeRef}
                                style={style}
                                className="bg-surface dark:bg-surface-dark p-4 rounded-input border border-border dark:border-border-dark relative"
                              >
                                <div className="absolute top-2 left-2 flex items-center gap-2">
                                  <button
                                    type="button"
                                    className="p-1 rounded-button border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-muted dark:text-text-muted-dark hover:border-action-dark hover:text-action-dark dark:hover:border-action dark:hover:text-action"
                                    {...attributes}
                                    {...listeners}
                                    aria-label="Drag to reorder"
                                  >
                                    <GripVertical className="w-4 h-4" />
                                  </button>
                                </div>
                                <div className="absolute top-2 right-10 flex gap-1">
                                  <button
                                    type="button"
                                    onClick={() => moveLinkUp(index)}
                                    disabled={index === 0}
                                    className={`p-1 rounded-button border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-muted dark:text-text-muted-dark hover:border-action-dark hover:text-action-dark dark:hover:border-action dark:hover:text-action disabled:opacity-40 disabled:cursor-not-allowed`}
                                    aria-label="Move link up"
                                  >
                                    <ChevronUp className="w-4 h-4" />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => moveLinkDown(index)}
                                    disabled={index === data.links.length - 1}
                                    className={`p-1 rounded-button border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-muted dark:text-text-muted-dark hover:border-action-dark hover:text-action-dark dark:hover:border-action dark:hover:text-action disabled:opacity-40 disabled:cursor-not-allowed`}
                                    aria-label="Move link down"
                                  >
                                    <ChevronDown className="w-4 h-4" />
                                  </button>
                                </div>
                                <button onClick={() => removeLink(link.id)} className="absolute top-2 right-2 text-text-muted-subtle dark:text-text-muted-dark hover:text-error-text dark:hover:text-error-text-dark hover:bg-error-bg dark:hover:bg-error-bg-dark rounded-full p-1 transition-colors" aria-label="Remove link">
                                  <X className="w-4 h-4"/>
                                </button>
                                <div className="grid gap-3 pt-6">
                                  <div className="flex gap-3 items-center">
                                    <div className="w-10 h-10 rounded-container bg-card dark:bg-surface-dark border border-border dark:border-border-dark flex items-center justify-center shrink-0">
                                      {React.createElement(ICON_MAP[link.icon], { className: "w-5 h-5 text-text-secondary dark:text-text-secondary-dark" })}
                                    </div>
                                    <input 
                                      type="text" 
                                      placeholder="Link Title (e.g. Download CV)"
                                      value={link.title}
                                      onChange={(e) => updateLink(link.id, 'title', e.target.value)}
                                      className="flex-1 bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-primary dark:text-text-primary-dark rounded-input px-3 py-2 text-sm focus:outline-none focus:border-action dark:focus:border-action-dark"
                                    />
                                  </div>
                                  <input 
                                    type="text" 
                                    placeholder="https://..."
                                    value={link.url}
                                    onChange={(e) => updateLink(link.id, 'url', e.target.value)}
                                    className="w-full bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-primary dark:text-text-primary-dark rounded-input px-3 py-2 text-sm focus:outline-none focus:border-action dark:focus:border-action-dark"
                                  />
                                  {/* Simple Icon Picker */}
                                  <div className="flex gap-2 overflow-x-auto pb-2 pt-1 no-scrollbar">
                                    {Object.keys(ICON_MAP).map(iconKey => (
                                      <button 
                                        key={iconKey}
                                        onClick={() => updateLink(link.id, 'icon', iconKey)}
                                        className={`p-2 rounded-button border flex-shrink-0 transition-all ${link.icon === iconKey ? 'bg-indigo-50 dark:bg-indigo-900/30 border-indigo-500 dark:border-indigo-400 text-indigo-600 dark:text-indigo-300' : 'bg-card dark:bg-surface-dark border-border dark:border-border-dark text-text-muted-subtle dark:text-text-muted-dark hover:border-border dark:hover:border-border-dark'}`}
                                        title={iconKey}
                                      >
                                        {React.createElement(ICON_MAP[iconKey], { className: "w-4 h-4" })}
                                      </button>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            )}
                          </SortableLinkItem>
                        ))}
                      </SortableContext>
                    </DndContext>
                    {data.links.length === 0 && (
                        <div className="text-center py-8 text-text-muted-subtle dark:text-text-muted-dark text-sm border-thick border-dashed border-border dark:border-border-dark rounded-input">
                            No custom links yet.
                        </div>
                    )}
                </div>
                )}
             </div>
           )}

           {activeTab === 'images' && (
              <div className="space-y-8">
                {settings?.allow_image_customisation === false ? (
                  <LockedOption message="Your organisation has disabled custom image uploads. Contact your administrator to enable this feature.">
                    <div className="space-y-8">
                      <ImageUpload label="Profile Picture" image={data.images.avatar} onUpload={() => {}} onRemove={() => {}} disabled={true} />
                      <ImageUpload label="Header Banner" image={data.images.banner} onUpload={() => {}} onRemove={() => {}} isBanner disabled={true} />
                    </div>
                  </LockedOption>
                ) : (
                  <>
                    {isUploading && <div className="text-center text-sm text-indigo-600 dark:text-indigo-400 animate-pulse">Uploading image...</div>}
                    <ImageUpload label="Profile Picture" image={data.images.avatar} onUpload={e => handleImageUpload('avatar', e)} onRemove={() => handleInputChange('images', 'avatar', null)} />
                    <ImageUpload label="Header Banner" image={data.images.banner} onUpload={e => handleImageUpload('banner', e)} onRemove={() => handleInputChange('images', 'banner', null)} isBanner />
                  </>
                )}
              </div>
           )}

            {activeTab === 'style' && (
               <div className="space-y-6">
                 {settings?.allow_theme_customisation === false ? (
                   <LockedOption message="Your organisation has disabled theme colour customisation. Your card will use the default theme colour.">
                     <div className="flex flex-wrap gap-4">
                       {(settings?.theme_colors || []).map(color => (
                         <div 
                          key={color.name} 
                          className={`w-12 h-12 rounded-full relative ${data.theme.color === color.name ? 'ring-4 ring-slate-200 scale-110' : ''}`}
                          style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                        >
                          {data.theme.color === color.name && <Check className="w-5 h-5 text-white absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10" />}
                        </div>
                       ))}
                     </div>
                   </LockedOption>
                 ) : (
                   <div className="flex flex-wrap gap-4">
                     {(settings?.theme_colors || []).map(color => (
                       <button 
                        key={color.name} 
                        onClick={() => handleInputChange('theme', 'color', color.name)} 
                        className={`w-12 h-12 rounded-full relative hover:scale-110 ${data.theme.color === color.name ? 'ring-4 ring-slate-200 scale-110' : ''}`}
                        style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                      >
                        {data.theme.color === color.name && <Check className="w-5 h-5 text-white absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10" />}
                      </button>
                     ))}
                   </div>
                 )}
               </div>
            )}

            {activeTab === 'privacy' && (
              <div className="space-y-6">
                {settings?.allow_privacy_customisation === false ? (
                  <LockedOption message="Your organisation has disabled privacy settings customisation. Privacy settings are controlled by your organisation.">
                    <div className="space-y-6">
                      <Toggle
                        label="Require Interaction"
                        description="Requires users to click a button to reveal email and phone. Prevents basic bots from seeing contact info in the initial page load."
                        checked={data.privacy?.requireInteraction ?? true}
                        onChange={() => {}}
                      />
                      <div className="h-px bg-border-subtle" />
                      <Toggle
                        label="Client-Side Obfuscation"
                        description="Encodes email and phone in the HTML to make scraping harder. Note: Determined scrapers can still decode this."
                        checked={data.privacy?.clientSideObfuscation ?? false}
                        onChange={() => {}}
                      />
                      <div className="h-px bg-border-subtle" />
                      <Toggle
                        label="Block Search Engines"
                        description="Adds meta robots tag to prevent search engines from indexing this card."
                        checked={data.privacy?.blockRobots ?? false}
                        onChange={() => {}}
                      />
                    </div>
                  </LockedOption>
                ) : (
                  <div className="space-y-6">
                    <Toggle
                      label="Require Interaction"
                      description="Requires users to click a button to reveal email and phone. Prevents basic bots from seeing contact info in the initial page load."
                      checked={data.privacy?.requireInteraction ?? true}
                      onChange={(checked) => handleInputChange('privacy', 'requireInteraction', checked)}
                    />
                    <div className="h-px bg-border-subtle" />
                    <Toggle
                      label="Client-Side Obfuscation"
                      description="Encodes email and phone in the HTML to make scraping harder. Note: Determined scrapers can still decode this."
                      checked={data.privacy?.clientSideObfuscation ?? false}
                      onChange={(checked) => handleInputChange('privacy', 'clientSideObfuscation', checked)}
                    />
                    <div className="h-px bg-border-subtle" />
                    <Toggle
                      label="Block Search Engines"
                      description="Adds meta robots tag to prevent search engines from indexing this card."
                      checked={data.privacy?.blockRobots ?? false}
                      onChange={(checked) => handleInputChange('privacy', 'blockRobots', checked)}
                    />
                  </div>
                )}
              </div>
            )}
        </div>
      </div>
      
      <div className="hidden lg:flex w-1/2 bg-border-subtle dark:bg-card-dark items-center justify-center p-10 relative">
          <div className="w-[375px] h-[750px] bg-card dark:bg-main-dark rounded-[3rem] shadow-2xl border-device border-text-primary dark:border-border-dark overflow-hidden relative">
            <CardDisplay data={data} settings={settings} darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
          </div>
      </div>
      <div className="fixed bottom-4 right-4 z-10 text-center group">
        <div className="flex justify-center">
          <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
          <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
        </div>
      </div>
    </div>
  );
}

function Input({ label, icon: Icon, value, onChange, type = "text", placeholder }) {
  return (
    <div className="space-y-1">
      {label && <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">{label}</label>}
      <div className="relative">
        {Icon && <Icon className="absolute left-4 top-3 w-5 h-5 text-text-muted-subtle dark:text-text-muted-dark" />}
        <input type={type} value={value || ''} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={`w-full ${Icon ? 'pl-11' : 'px-4'} py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark placeholder:text-text-muted-subtle dark:placeholder:text-text-muted-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark`} />
      </div>
    </div>
  );
}

function LockedOption({ message, children }) {
  return (
    <div className="relative">
      <div className="opacity-50 pointer-events-none">
        {children}
      </div>
      <div className="absolute inset-0 flex items-center justify-center bg-surface/80 dark:bg-card-dark/80 rounded-container border-thick border-dashed border-border dark:border-border-dark">
        <div className="bg-input-bg dark:bg-input-bg-dark rounded-container p-4 border border-border dark:border-border-dark shadow-lg max-w-sm mx-4">
          <div className="flex items-center gap-3 mb-2">
            <Lock className="w-5 h-5 text-text-muted dark:text-text-muted-dark" />
            <span className="text-sm font-semibold text-text-primary dark:text-text-secondary-dark">Locked by Organisation</span>
          </div>
          <p className="text-xs text-text-secondary dark:text-text-muted-dark">{message}</p>
        </div>
      </div>
    </div>
  );
}

function TextArea({ label, value, onChange }) {
  return (
    <div className="space-y-1">
      <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">{label}</label>
      <textarea value={value || ''} onChange={(e) => onChange(e.target.value)} rows={3} className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark resize-none" />
    </div>
  );
}

function Toggle({ label, description, checked, onChange }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">{label}</label>
          {description && <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">{description}</p>}
        </div>
        <button
          type="button"
          onClick={() => onChange(!checked)}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:ring-offset-2 ${
            checked ? 'bg-action dark:bg-action-dark' : 'bg-border dark:bg-surface-dark'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              checked ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
        </button>
      </div>
    </div>
  );
}

function ImageUpload({ label, image, onUpload, onRemove, isBanner, disabled = false }) {
  return (
    <section>
      <h3 className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-3">{label}</h3>
      <div className={`relative ${isBanner ? 'w-full h-32' : 'w-24 h-24'} rounded-input bg-surface dark:bg-surface-dark border-thick border-dashed border-border dark:border-border-dark flex items-center justify-center overflow-hidden group ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:border-border-dark dark:hover:border-border-dark'} transition-colors`}>
        {image ? <img src={image} className="w-full h-full object-cover" alt="upload" /> : <div className="text-center text-text-muted-subtle dark:text-text-muted-dark pointer-events-none"><Upload className="w-6 h-6 mx-auto mb-1" /><span className="text-xs">Upload</span></div>}
        <input type="file" accept="image/*" onChange={onUpload} disabled={disabled} className="absolute inset-0 opacity-0 cursor-pointer appearance-none bg-transparent focus:outline-none disabled:cursor-not-allowed" />
      </div>
      {image && !disabled && <button onClick={onRemove} className="mt-2 text-sm text-red-500 dark:text-red-400 font-medium hover:text-red-600 dark:hover:text-red-300">Remove</button>}
    </section>
  );
}

function SocialIcon({ url, icon: Icon, label, themeColor }) {
  if (!url) return null;
  // Use theme color if available, otherwise default to indigo
  const hoverColor = themeColor?.buttonStyle || themeColor?.textStyle || '#4f46e5';
  return (
    <a href={url} target="_blank" rel="noreferrer" className="flex flex-col items-center gap-2 group">
      <div className="w-full aspect-square rounded-card bg-surface dark:bg-surface-dark border border-border-subtle dark:border-border-dark flex items-center justify-center text-text-secondary dark:text-text-secondary-dark group-hover:scale-105 transition-transform group-hover:shadow-md group-hover:text-white" style={{ '--hover-bg': hoverColor }}>
        <style>{`.group:hover div { background-color: ${hoverColor}; border-color: ${hoverColor}; }`}</style>
        <Icon className="w-6 h-6" />
      </div>
      <span className="text-[10px] uppercase font-bold tracking-wider text-text-muted-subtle dark:text-text-muted-dark">{label}</span>
    </a>
  );
}

// Color Selector Component
function ColorSelector({ selectedColor, onSelect, label, showAuto = false, autoLabel = "Auto (complementary)" }) {
  const colorGradients = {
    indigo: 'from-indigo-500 to-indigo-700',
    blue: 'from-blue-500 to-blue-700',
    rose: 'from-rose-500 to-rose-700',
    emerald: 'from-emerald-500 to-emerald-700',
    slate: 'from-slate-500 to-slate-700',
    purple: 'from-purple-500 to-purple-700',
    cyan: 'from-cyan-500 to-cyan-700',
    teal: 'from-teal-500 to-teal-700',
    orange: 'from-orange-500 to-orange-700',
    pink: 'from-pink-500 to-pink-700',
    violet: 'from-violet-500 to-violet-700',
    fuchsia: 'from-fuchsia-500 to-fuchsia-700',
    amber: 'from-amber-500 to-amber-700',
    lime: 'from-lime-500 to-lime-700',
    green: 'from-green-500 to-green-700',
    yellow: 'from-yellow-500 to-yellow-700',
    red: 'from-red-500 to-red-700'
  };

  return (
    <div>
      {label && <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">{label}</label>}
      <div className="grid grid-cols-8 gap-2">
        {showAuto && (
          <button
            onClick={() => onSelect(null)}
            className={`w-10 h-10 rounded-full border-thick flex flex-col items-center justify-center text-[10px] font-medium transition-all ${
              selectedColor === null 
                ? 'border-indigo-500 dark:border-indigo-400 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 ring-2 ring-indigo-200 dark:ring-indigo-800' 
                : 'border-border dark:border-border-dark bg-surface dark:bg-surface-dark text-text-secondary dark:text-text-secondary-dark hover:border-border-dark dark:hover:border-border-dark'
            }`}
          >
            <span>Auto</span>
          </button>
        )}
        {TAILWIND_COLORS.map(color => (
          <button
            key={color}
            onClick={() => onSelect(color)}
            className={`w-10 h-10 rounded-full border-thick transition-all overflow-hidden ${
              selectedColor === color
                ? 'border-indigo-500 dark:border-indigo-400 ring-2 ring-indigo-200 dark:ring-indigo-800 scale-105'
                : 'border-border dark:border-border-dark hover:border-border-dark dark:hover:border-border-dark'
            }`}
            title={color.charAt(0).toUpperCase() + color.slice(1)}
          >
            <div className={`w-full h-full bg-gradient-to-br ${colorGradients[color] || 'from-gray-500 to-gray-700'}`} />
          </button>
        ))}
      </div>
    </div>
  );
}

function UserManagementView({ apiCall, userRole, onBack, showAlert, showConfirm }) {
  const [users, setUsers] = useState([]);
  const [invitations, setInvitations] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [editingUserId, setEditingUserId] = useState(null);
  const [currentUserId, setCurrentUserId] = useState(null);
  
  const [newUser, setNewUser] = useState({ email: '', password: '', role: 'member' });
  const [newInvitation, setNewInvitation] = useState({ email: '', role: 'member' });
  const [isSaving, setIsSaving] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  useEffect(() => {
    fetchCurrentUser();
    fetchUsers();
    fetchInvitations();
  }, []);

  const fetchCurrentUser = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/auth/me`);
      if (res.ok) {
        const userData = await res.json();
        setCurrentUserId(userData.id);
      }
    } catch (e) {
      console.error('Failed to fetch current user:', e);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users`);
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      } else {
        if (showAlert) showAlert('Failed to load users', 'error');
      }
    } catch (e) {
      console.error('Failed to fetch users:', e);
      if (showAlert) showAlert('Error loading users', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchInvitations = async () => {
    try {
      // We'll need to add an endpoint to list invitations, or we can skip this for now
      // For now, we'll just fetch users
    } catch (e) {
      console.error('Failed to fetch invitations:', e);
    }
  };

  const handleCreateUser = async () => {
    if (!newUser.email || !newUser.password) {
      if (showAlert) showAlert('Email and password are required', 'error');
      return;
    }

    if (newUser.password.length < 8) {
      if (showAlert) showAlert('Password must be at least 8 characters long', 'error');
      return;
    }

    setIsSaving(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users`, {
        method: 'POST',
        body: JSON.stringify(newUser)
      });
      
      if (res.ok) {
        setIsSuccess(true);
        setTimeout(() => setIsSuccess(false), 2000);
        setShowCreateUserModal(false);
        setNewUser({ email: '', password: '', role: 'member' });
        fetchUsers();
      } else {
        // Try to parse error response
        let errorMessage = 'Failed to create user';
        try {
          const errorData = await res.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
          console.error('User creation failed:', {
            status: res.status,
            statusText: res.statusText,
            error: errorData
          });
        } catch (parseError) {
          // Response is not JSON, use status text
          console.error('User creation failed - non-JSON response:', {
            status: res.status,
            statusText: res.statusText
          });
          errorMessage = `Failed to create user: ${res.status} ${res.statusText}`;
        }
        if (showAlert) showAlert(errorMessage, 'error');
      }
    } catch (e) {
      console.error('Error creating user:', e);
      const errorMessage = e.message || 'Error creating user. Please try again.';
      if (showAlert) showAlert(errorMessage, 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const handleSendInvitation = async () => {
    if (!newInvitation.email) {
      if (showAlert) showAlert('Email is required', 'error');
      return;
    }

    setIsSaving(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/invitations`, {
        method: 'POST',
        body: JSON.stringify(newInvitation)
      });
      if (res.ok) {
        setIsSuccess(true);
        setTimeout(() => setIsSuccess(false), 2000);
        setShowInviteModal(false);
        setNewInvitation({ email: '', role: 'member' });
      } else {
        const errorData = await res.json().catch(() => ({}));
        if (showAlert) showAlert(errorData.error || 'Failed to send invitation', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error sending invitation', 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const handleUpdateRole = async (userId, newRole) => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ role: newRole })
      });
      if (res.ok) {
        if (showAlert) showAlert('User role updated successfully', 'success');
        fetchUsers();
        setEditingUserId(null);
      } else {
        const errorData = await res.json().catch(() => ({}));
        if (showAlert) showAlert(errorData.error || 'Failed to update role', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error updating role', 'error');
    }
  };

  const handleRemoveUser = async (userId, userEmail) => {
    if (showConfirm) {
      showConfirm(
        `Are you sure you want to remove ${userEmail} from the organisation?`,
        async () => {
          try {
            const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
              method: 'DELETE'
            });
            if (res.ok) {
              if (showAlert) showAlert('User removed successfully', 'success');
              fetchUsers();
            } else {
              const errorData = await res.json().catch(() => ({}));
              if (showAlert) showAlert(errorData.error || 'Failed to remove user', 'error');
            }
          } catch (e) {
            if (showAlert) showAlert('Error removing user', 'error');
          }
        },
        'Remove User',
        'Remove',
        'Cancel'
      );
    }
  };

  if (userRole !== 'owner') {
    return (
      <div className="min-h-screen bg-main dark:bg-main-dark flex items-center justify-center p-6">
        <div className="bg-card dark:bg-card-dark rounded-card p-8 shadow-lg max-w-md w-full">
          <h2 className="text-xl font-bold text-text-primary dark:text-text-primary-dark mb-4">Access Denied</h2>
          <p className="text-text-secondary dark:text-text-muted-dark mb-6">You don't have permission to manage users.</p>
          <button onClick={onBack} className="px-4 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold">
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex flex-col">
      <div className="w-full bg-card dark:bg-card-dark border-b border-border dark:border-border-dark">
        <div className="p-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="p-2 hover:bg-surface dark:hover:bg-surface-dark rounded-full text-text-muted dark:text-text-muted-dark">
              <ArrowLeft className="w-5 h-5"/>
            </button>
            <div>
              <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">User Management</h1>
              <p className="text-sm text-text-secondary dark:text-text-muted-dark">Manage users and invitations for your organisation</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setShowInviteModal(true)}
              className="px-4 py-2 bg-action dark:bg-action-dark text-white rounded-full text-sm font-bold flex items-center gap-2 hover:bg-action-hover dark:hover:bg-action-hover-dark"
            >
              <Plus className="w-4 h-4" /> Invite User
            </button>
            <button
              onClick={() => setShowCreateUserModal(true)}
              className="px-4 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold flex items-center gap-2 hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark"
            >
              <Plus className="w-4 h-4" /> Create User
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 p-6 max-w-6xl mx-auto w-full">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="text-text-secondary dark:text-text-muted-dark">Loading users...</div>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="bg-card dark:bg-card-dark rounded-input shadow-sm border border-border dark:border-border-dark overflow-hidden">
              <div className="p-6 border-b border-border dark:border-border-dark">
                <h2 className="text-lg font-semibold text-text-primary dark:text-text-primary-dark">Organisation Users</h2>
                <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Users currently in your organisation</p>
              </div>
              <div className="divide-y divide-slate-200 dark:divide-slate-700">
                {users.length === 0 ? (
                  <div className="p-6 text-center text-text-muted dark:text-text-muted-dark">
                    No users found
                  </div>
                ) : (
                  users.map((user) => {
                    const isCurrentUser = user.id === currentUserId;
                    return (
                      <div key={user.id} className="p-6 flex items-center justify-between hover:bg-surface dark:hover:bg-surface-dark/50 transition-colors">
                        <div className="flex-1">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center">
                              <User className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                            </div>
                            <div>
                              <div className="font-medium text-text-primary dark:text-text-primary-dark flex items-center gap-2">
                                {user.email}
                                {isCurrentUser && (
                                  <span className="text-xs text-text-muted dark:text-text-muted-dark">(You)</span>
                                )}
                              </div>
                              <div className="text-sm text-text-muted dark:text-text-muted-dark">
                                {user.role === 'owner' ? (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300">
                                    Owner
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark">
                                    Member
                                  </span>
                                )}
                                <span className="ml-2">Joined {new Date(user.created_at).toLocaleDateString()}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {isCurrentUser ? (
                            <span className="text-xs text-text-muted dark:text-text-muted-dark italic">Cannot modify yourself</span>
                          ) : editingUserId === user.id ? (
                            <div className="flex items-center gap-2">
                              <select
                                value={user.role}
                                onChange={(e) => handleUpdateRole(user.id, e.target.value)}
                                className="px-3 py-1.5 text-sm rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark"
                              >
                                <option value="member">Member</option>
                                <option value="owner">Owner</option>
                              </select>
                              <button
                                onClick={() => setEditingUserId(null)}
                                className="px-3 py-1.5 text-sm bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <>
                              <button
                                onClick={() => setEditingUserId(user.id)}
                                className="px-3 py-1.5 text-sm bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark flex items-center gap-1"
                              >
                                <Edit3 className="w-3 h-3" /> Change Role
                              </button>
                              <button
                                onClick={() => handleRemoveUser(user.id, user.email)}
                                className="px-3 py-1.5 text-sm bg-error-bg dark:bg-error-bg-dark text-error dark:text-error-text-dark rounded-badge hover:bg-error-bg dark:hover:bg-error-bg-dark flex items-center gap-1"
                              >
                                <Trash2 className="w-3 h-3" /> Remove
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreateUserModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
            <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Create New User</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Email</label>
                <input
                  type="email"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                  placeholder="user@example.com"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Password</label>
                <input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                  placeholder="Minimum 8 characters"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Role</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                >
                  <option value="member">Member</option>
                  <option value="owner">Owner</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowCreateUserModal(false);
                  setNewUser({ email: '', password: '', role: 'member' });
                }}
                className="flex-1 px-4 py-2.5 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateUser}
                disabled={isSaving}
                className="flex-1 px-4 py-2.5 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-button font-bold hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isSaving ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : isSuccess ? (
                  <Check className="w-4 h-4 text-green-500" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {isSaving ? 'Creating...' : 'Create User'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Invite User Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
            <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Invite User</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Email</label>
                <input
                  type="email"
                  value={newInvitation.email}
                  onChange={(e) => setNewInvitation({ ...newInvitation, email: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                  placeholder="user@example.com"
                />
                <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">An invitation email will be sent to this address</p>
              </div>
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Role</label>
                <select
                  value={newInvitation.role}
                  onChange={(e) => setNewInvitation({ ...newInvitation, role: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                >
                  <option value="member">Member</option>
                  <option value="owner">Owner</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowInviteModal(false);
                  setNewInvitation({ email: '', role: 'member' });
                }}
                className="flex-1 px-4 py-2.5 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
              >
                Cancel
              </button>
              <button
                onClick={handleSendInvitation}
                disabled={isSaving}
                className="flex-1 px-4 py-2.5 bg-action dark:bg-action-dark text-white rounded-button font-bold hover:bg-action-hover dark:hover:bg-action-hover-dark disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isSaving ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : isSuccess ? (
                  <Check className="w-4 h-4 text-green-500" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {isSaving ? 'Sending...' : 'Send Invitation'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SettingsView({ settings, setSettings, onBack, onSave, apiCall, showAlert, showConfirm }) {
  // Initialize local settings with extracted base colors from existing data
  const initializeColorData = (colors) => {
    return colors.map(color => {
      let hexBase, baseColor, colorType;
      
      // Determine if this is a standard color (has Tailwind gradient or baseColor) or custom hex
      const hasValidTailwindGradient = color.gradient && typeof color.gradient === 'string' && color.gradient.startsWith('from-');
      const hasHexBase = color.hexBase && typeof color.hexBase === 'string' && color.hexBase.startsWith('#');
      
      if (hasValidTailwindGradient) {
        // Convert from Tailwind gradient to hex
        const extracted = extractBaseColorFromGradient(color.gradient);
        if (extracted) {
          baseColor = extracted.baseColor;
          hexBase = getTailwindColorHex(extracted.baseColor, 600); // Always use shade 600
          colorType = 'standard';
        } else {
          // Fallback if extraction fails
          baseColor = color.baseColor || 'indigo';
          hexBase = hasHexBase ? color.hexBase : getTailwindColorHex(baseColor, 600);
          colorType = color.colorType === 'custom' ? 'custom' : 'standard';
        }
      } else if (hasHexBase) {
        // Has hexBase - determine if standard or custom
        if (color.baseColor && color.colorType !== 'custom') {
          // Standard color with hexBase
          baseColor = color.baseColor;
          hexBase = color.hexBase;
          colorType = 'standard';
        } else {
          // Custom hex color
          baseColor = null;
          hexBase = color.hexBase;
          colorType = 'custom';
        }
      } else if (color.gradientStyle) {
        // Has gradientStyle but no hexBase - extract from gradientStyle or use default
        baseColor = null;
        hexBase = '#4f46e5'; // Default
        colorType = 'custom';
      } else {
        // Fallback - treat as standard with default
        baseColor = color.baseColor || 'indigo';
        hexBase = getTailwindColorHex(baseColor, 600);
        colorType = color.colorType === 'custom' ? 'custom' : 'standard';
      }
      
      // Always auto-generate complementary secondary color
      const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
      const hexSecondary = color.hexSecondary || (complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase);
      
      // Generate all inline styles
      const gradientStyle = `linear-gradient(135deg, ${hexBase}, ${hexSecondary})`;
      const buttonStyle = hexBase;
      const linkStyle = hexBase;
      const textStyle = hexBase;
      
      // Build clean hex-only color object
      return {
        name: color.name,
        colorType: colorType,
        baseColor: baseColor, // null for custom, Tailwind name for standard
        hexBase: hexBase,
        hexSecondary: hexSecondary,
        gradientStyle: gradientStyle,
        buttonStyle: buttonStyle,
        linkStyle: linkStyle,
        textStyle: textStyle
      };
    });
  };

  const [localSettings, setLocalSettings] = useState({
    ...settings,
    theme_colors: initializeColorData(settings.theme_colors || []),
    theme_variant: settings.theme_variant || 'default',
    // Initialize override toggles - default to true if undefined, but preserve false
    allow_theme_customisation: settings.allow_theme_customisation !== undefined ? Boolean(settings.allow_theme_customisation) : true,
    allow_image_customisation: settings.allow_image_customisation !== undefined ? Boolean(settings.allow_image_customisation) : true,
    allow_links_customisation: settings.allow_links_customisation !== undefined ? Boolean(settings.allow_links_customisation) : true,
    allow_privacy_customisation: settings.allow_privacy_customisation !== undefined ? Boolean(settings.allow_privacy_customisation) : true
  });
  const [editingColorIndex, setEditingColorIndex] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [isOrganisationNameOpen, setIsOrganisationNameOpen] = useState(false);
  const [isCustomizationControlsOpen, setIsCustomizationControlsOpen] = useState(false);
  const [isThemeColorsOpen, setIsThemeColorsOpen] = useState(false);
  const [isAppThemesOpen, setIsAppThemesOpen] = useState(false);

  const applyThemePreset = (variant) => {
    setEditingColorIndex(null);
    const preset = THEME_PRESETS?.[variant];
    setLocalSettings(prev => ({
      ...prev,
      theme_variant: preset ? variant : 'custom',
      theme_colors: preset ? initializeColorData(preset) : prev.theme_colors
    }));
  };

  // Re-initialize when settings prop changes
  useEffect(() => {
    setLocalSettings({
      ...settings,
      theme_colors: initializeColorData(settings.theme_colors || []),
      theme_variant: settings.theme_variant || localSettings.theme_variant || 'swiish',
      // Initialize override toggles - default to true if undefined, but preserve false
      allow_theme_customisation: settings.allow_theme_customisation !== undefined ? Boolean(settings.allow_theme_customisation) : true,
      allow_image_customisation: settings.allow_image_customisation !== undefined ? Boolean(settings.allow_image_customisation) : true,
      allow_links_customisation: settings.allow_links_customisation !== undefined ? Boolean(settings.allow_links_customisation) : true,
      allow_privacy_customisation: settings.allow_privacy_customisation !== undefined ? Boolean(settings.allow_privacy_customisation) : true
    });
  }, [settings]);

  // Apply app theme variant class to body for CSS overrides (swiish|minimal|custom)
  useEffect(() => {
    const variant = localSettings.theme_variant || settings.theme_variant || 'swiish';
    document.body.classList.remove('theme-swiish', 'theme-minimal', 'theme-custom');
    document.body.classList.add(`theme-${variant}`);
    applyThemeCssVars(variant);
  }, [localSettings.theme_variant, settings.theme_variant]);

  const handleSave = async () => {
    setIsSaving(true);
    const startTime = Date.now();
    try {
      // Save hex-only color structure
      const colorsToSave = localSettings.theme_colors.map(color => {
        return {
          name: color.name,
          colorType: color.colorType || 'standard',
          baseColor: color.baseColor || null, // null for custom, Tailwind name for standard
          hexBase: color.hexBase || '#4f46e5',
          hexSecondary: color.hexSecondary || color.hexBase || '#4f46e5',
          gradientStyle: color.gradientStyle || `linear-gradient(135deg, ${color.hexBase || '#4f46e5'}, ${color.hexSecondary || color.hexBase || '#4f46e5'})`,
          buttonStyle: color.buttonStyle || color.hexBase || '#4f46e5',
          linkStyle: color.linkStyle || color.hexBase || '#4f46e5',
          textStyle: color.textStyle || color.hexBase || '#4f46e5'
        };
      });

      const res = await apiCall(`${API_ENDPOINT}/admin/settings`, {
        method: 'POST',
        body: JSON.stringify({
          default_organisation: localSettings.default_organisation,
          theme_colors: colorsToSave,
          theme_variant: localSettings.theme_variant || 'swiish',
          allow_theme_customisation: Boolean(localSettings.allow_theme_customisation),
          allow_image_customisation: Boolean(localSettings.allow_image_customisation),
          allow_links_customisation: Boolean(localSettings.allow_links_customisation),
          allow_privacy_customisation: Boolean(localSettings.allow_privacy_customisation)
        })
      });

      // Ensure at least 500ms has passed
      const elapsedTime = Date.now() - startTime;
      if (elapsedTime < 500) {
        await new Promise(resolve => setTimeout(resolve, 500 - elapsedTime));
      }

      if (res.ok) {
        // Refetch from server to get the latest saved data
        setIsSuccess(true);
        setTimeout(() => setIsSuccess(false), 2000);
        await onSave();
      } else {
        const errorData = await res.json().catch(() => ({}));
        console.error('Save failed:', errorData);
        if (showAlert) showAlert('Failed to save settings', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error saving settings', 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const addColor = () => {
    const baseColor = 'indigo';
    const hexBase = getTailwindColorHex(baseColor, 600);
    const complementary = getComplementaryColor(baseColor);
    const hexSecondary = getTailwindColorHex(complementary, 600);
    
    const newColor = {
      name: `color${localSettings.theme_colors.length + 1}`,
      colorType: 'standard',
      baseColor: baseColor,
      hexBase: hexBase,
      hexSecondary: hexSecondary,
      gradientStyle: `linear-gradient(135deg, ${hexBase}, ${hexSecondary})`,
      buttonStyle: hexBase,
      linkStyle: hexBase,
      textStyle: hexBase
    };
    setLocalSettings(prev => {
      const newColors = [...prev.theme_colors, newColor];
      setEditingColorIndex(newColors.length - 1);
      return {
        ...prev,
        theme_colors: newColors,
        theme_variant: 'custom'
      };
    });
  };

  const updateColor = (colorIndex, field, value) => {
    setLocalSettings(prev => {
      const updated = prev.theme_colors.map((c, idx) => {
        if (idx === colorIndex) {
          const updatedColor = { ...c, [field]: value };
          const currentColorType = updatedColor.colorType || c.colorType || 'standard';
          
          // Handle colorType changes
          if (field === 'colorType') {
            if (value === 'standard' && !updatedColor.baseColor) {
              // Switching to standard - set default baseColor if missing
              updatedColor.baseColor = c.baseColor || 'indigo';
              updatedColor.hexBase = c.hexBase || getTailwindColorHex(updatedColor.baseColor, 600);
            } else if (value === 'custom') {
              // Switching to custom - clear baseColor
              updatedColor.baseColor = null;
            }
          }
          
          // For standard colors: when baseColor changes, update hexBase
          if (currentColorType === 'standard' && field === 'baseColor') {
            updatedColor.hexBase = getTailwindColorHex(value, 600);
          }
          
          // For custom colors: when hexBase changes, ensure colorType is custom
          if (field === 'hexBase') {
            if (currentColorType !== 'custom') {
              updatedColor.colorType = 'custom';
              updatedColor.baseColor = null;
            }
          }
          
          // Handle hexBase
          let hexBase = updatedColor.hexBase || c.hexBase;
          let baseColor = updatedColor.baseColor || c.baseColor;
          
          // If hexBase is missing, generate it
          if (!hexBase) {
            if (baseColor) {
              hexBase = getTailwindColorHex(baseColor, 600);
              updatedColor.hexBase = hexBase;
            } else {
              hexBase = '#4f46e5'; // Default
              updatedColor.hexBase = hexBase;
            }
          }
          
          // Handle hexSecondary
          let hexSecondary;
          
          if (currentColorType === 'standard') {
            // Standard colors always use auto-complementary
            const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
            hexSecondary = complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase;
            updatedColor.hexSecondary = hexSecondary;
          } else if (currentColorType === 'custom') {
            // Custom colors: allow manual setting
            if (field === 'hexSecondary') {
              // User is manually setting hexSecondary
              hexSecondary = value || null;
              updatedColor.hexSecondary = hexSecondary;
            } else if (field === 'baseColor' || field === 'hexBase' || field === 'colorType') {
              // When baseColor/hexBase changes, only auto-generate if hexSecondary is not manually set
              const existingHexSecondary = c.hexSecondary;
              if (!existingHexSecondary || existingHexSecondary === '') {
                // Auto-generate complementary
                const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
                hexSecondary = complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase;
                updatedColor.hexSecondary = hexSecondary;
              } else {
                // Keep existing manual value
                hexSecondary = existingHexSecondary;
                updatedColor.hexSecondary = hexSecondary;
              }
            } else {
              // Keep existing value
              hexSecondary = updatedColor.hexSecondary || c.hexSecondary || hexBase;
              updatedColor.hexSecondary = hexSecondary;
            }
          } else {
            // Fallback
            hexSecondary = updatedColor.hexSecondary || c.hexSecondary || hexBase;
            updatedColor.hexSecondary = hexSecondary;
          }
          
          // Always regenerate inline styles when relevant fields change
          if (field === 'baseColor' || field === 'colorType' || field === 'hexBase' || field === 'hexSecondary') {
            const finalHexSecondary = hexSecondary || hexBase;
            updatedColor.gradientStyle = `linear-gradient(135deg, ${hexBase}, ${finalHexSecondary})`;
            updatedColor.buttonStyle = hexBase;
            updatedColor.linkStyle = hexBase;
            updatedColor.textStyle = hexBase;
          }
          
          return updatedColor;
        }
        return c;
      });
      return { ...prev, theme_colors: updated, theme_variant: 'custom' };
    });
  };

  const removeColor = (colorIndex) => {
    if (localSettings.theme_colors.length <= 1) {
      if (showAlert) showAlert('You must have at least one color', 'error');
      return;
    }
    const colorName = localSettings.theme_colors[colorIndex]?.name;
    if (showConfirm) {
      showConfirm(
        `Delete color "${colorName}"?`,
        () => {
          setLocalSettings(prev => ({
            ...prev,
            theme_colors: prev.theme_colors.filter((c, idx) => idx !== colorIndex),
            theme_variant: 'custom'
          }));
          if (editingColorIndex === colorIndex) {
            setEditingColorIndex(null);
          } else if (editingColorIndex !== null && editingColorIndex > colorIndex) {
            // Adjust index if we deleted a color before the one being edited
            setEditingColorIndex(editingColorIndex - 1);
          }
        },
        'Delete Color',
        'Delete',
        'Cancel'
      );
    }
  };

  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex flex-col lg:flex-row">
      <div className="w-full lg:w-1/2 bg-card dark:bg-card-dark border-r border-border dark:border-border-dark h-auto lg:h-screen overflow-y-auto flex flex-col">
        <div className="p-6 border-b border-border-subtle dark:border-border-dark flex items-center justify-between bg-card dark:bg-card-dark sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="p-2 hover:bg-surface dark:hover:bg-surface-dark rounded-full text-text-muted dark:text-text-muted-dark">
              <ArrowLeft className="w-5 h-5"/>
            </button>
            <div>
              <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">Organisation Settings</h1>
            </div>
          </div>
          <button 
            onClick={handleSave} 
            disabled={isSaving}
            className="px-5 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold flex items-center gap-2 hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark transition-colors disabled:opacity-50"
          >
            {isSaving ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : isSuccess ? (
              <Check className="w-4 h-4 text-green-500" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {isSaving ? 'Saving...' : 'Save'}
          </button>
        </div>

        <div className="flex-1 p-6 space-y-6">
          <div className="space-y-6">
            {/* Organisation Name Section */}
            <div>
              <button
                onClick={() => setIsOrganisationNameOpen(!isOrganisationNameOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">Organisation Name</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">This organisation name will be applied to all cards in your organisation. Users cannot change this.</p>
                </div>
                {isOrganisationNameOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>
              
              {isOrganisationNameOpen && (
                <div className="mt-4 p-4 bg-surface dark:bg-card-dark/50 rounded-input">
                  <input
                    type="text"
                    value={localSettings.default_organisation || ''}
                    onChange={(e) => setLocalSettings(prev => ({ ...prev, default_organisation: e.target.value }))}
                    className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                    placeholder="Organisation Name"
                  />
                </div>
              )}
            </div>

            <div className="h-px bg-surface dark:bg-surface-dark" />

            {/* Organization Override Toggles */}
            <div className="space-y-6">
              <button
                onClick={() => setIsCustomizationControlsOpen(!isCustomizationControlsOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">User Customisation Controls</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Control what users in your organisation can customise on their cards.</p>
                </div>
                {isCustomizationControlsOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>
              
              {isCustomizationControlsOpen && (
                <div className="mt-4 space-y-4">
                  {/* Theme Customization Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Theme Customisation</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can choose theme colors for their cards.</p>
                </div>
                <Toggle
                  label="Allow users to choose theme colors"
                  description="When enabled, users can select from your organisation's theme colour palette. When disabled, cards will use the first colour in your palette."
                  checked={localSettings.allow_theme_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_theme_customisation: checked }))}
                />
              </div>

              {/* Image Customization Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Image Customisation</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can upload custom avatars and banner images.</p>
                </div>
                <Toggle
                  label="Allow users to upload custom avatars and banners"
                  description="When enabled, users can upload their own images. When disabled, image uploads will be blocked."
                  checked={localSettings.allow_image_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_image_customisation: checked }))}
                />
              </div>

              {/* Links Customization Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Links Customisation</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can add custom links to their cards.</p>
                </div>
                <Toggle
                  label="Allow users to add custom links"
                  description="When enabled, users can add custom links to their cards. When disabled, the links section will be locked."
                  checked={localSettings.allow_links_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_links_customisation: checked }))}
                />
              </div>

              {/* Privacy Settings Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Privacy Settings</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can change privacy settings on their cards.</p>
                </div>
                <Toggle
                  label="Allow users to change privacy settings"
                  description="When enabled, users can modify privacy options (require interaction, obfuscation, block robots). When disabled, privacy settings will be locked to organisation defaults."
                  checked={localSettings.allow_privacy_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_privacy_customisation: checked }))}
                />
              </div>
                </div>
              )}
            </div>

            <div className="h-px bg-surface dark:bg-surface-dark" />

            {/* App Themes */}
            <div>
              <button
                onClick={() => setIsAppThemesOpen(!isAppThemesOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">App Themes</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Choose the look for the app UI (backgrounds, chrome, buttons).</p>
                </div>
                {isAppThemesOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>

              {isAppThemesOpen && (
                <div className="mt-4 space-y-3">
                  {[
                    { id: 'swiish', title: 'Swiish', desc: 'Original Swiish theme with colors and textures.' },
                    { id: 'minimal', title: 'Minimal', desc: 'Black/white, few grays, no textures, border-only accents.' },
                  ].map(opt => (
                    <label
                      key={opt.id}
                      className="flex items-start gap-3 p-3 rounded-input border border-border dark:border-border-dark bg-surface dark:bg-surface-dark hover:bg-card dark:hover:bg-card-dark transition-colors cursor-pointer"
                    >
                      <input
                        type="radio"
                        name="app-theme"
                        className="mt-1"
                        value={opt.id}
                        checked={(localSettings.theme_variant || 'swiish') === opt.id}
                        onChange={(e) => applyThemePreset(e.target.value)}
                      />
                      <div>
                        <div className="font-medium text-text-primary dark:text-text-primary-dark">{opt.title}</div>
                        <p className="text-sm text-text-secondary dark:text-text-muted-dark">{opt.desc}</p>
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div className="h-px bg-surface dark:bg-surface-dark" />

            {/* Profile Colors */}
            <div>
              <button
                onClick={() => setIsThemeColorsOpen(!isThemeColorsOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">Profile Colors</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Manage the color palette available for user cards.</p>
                </div>
                {isThemeColorsOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>
              
              {isThemeColorsOpen && (
                <div className="mt-4 space-y-4">
                  <div className="flex justify-end">
                      <button 
                        onClick={addColor}
                        className="text-sm font-bold text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 flex items-center gap-1 px-4 py-2 bg-indigo-50 dark:bg-indigo-900/30 rounded-badge hover:bg-indigo-100 dark:hover:bg-indigo-900/50 transition-colors"
                      >
                        <Plus className="w-4 h-4" /> Add Color
                      </button>
                    </div>

              <div className="space-y-4">
                {localSettings.theme_colors?.map((color, index) => (
                  <div key={index} className="bg-surface dark:bg-surface-dark p-4 rounded-input border border-border dark:border-border-dark">
                    {editingColorIndex === index ? (
                      <div className="space-y-4">
                        <div className="flex justify-between items-center">
                          <h4 className="font-medium text-text-primary dark:text-text-primary-dark">Editing: {color.name}</h4>
                          <div className="flex gap-2">
                            <button
                              onClick={() => setEditingColorIndex(null)}
                              className="px-3 py-1 text-sm bg-card dark:bg-surface-dark border border-border dark:border-border-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark text-text-primary dark:text-text-primary-dark"
                            >
                              Done
                            </button>
                            <button
                              onClick={() => removeColor(index)}
                              className="px-3 py-1 text-sm bg-error-bg dark:bg-error-bg-dark text-error dark:text-error-text-dark border border-error-border dark:border-error-border-dark rounded-badge hover:bg-error-bg dark:hover:bg-error-bg-dark"
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                        
                        <Input
                          label="Color Name"
                          value={color.name}
                          onChange={(v) => updateColor(index, 'name', v)}
                        />

                        <div>
                          <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Color Type</label>
                          <div className="flex gap-2">
                            <button
                              onClick={() => updateColor(index, 'colorType', 'standard')}
                              className={`flex-1 px-4 py-2 rounded-button border transition-all ${
                                (color.colorType || 'standard') === 'standard'
                                  ? 'bg-indigo-50 dark:bg-indigo-900/30 border-indigo-500 dark:border-indigo-400 text-indigo-700 dark:text-indigo-300 font-medium'
                                  : 'bg-card dark:bg-surface-dark border-border dark:border-border-dark text-text-secondary dark:text-text-secondary-dark hover:bg-surface dark:hover:bg-surface-dark'
                              }`}
                            >
                              Standard Colors
                            </button>
                            <button
                              onClick={() => updateColor(index, 'colorType', 'custom')}
                              className={`flex-1 px-4 py-2 rounded-button border transition-all ${
                                color.colorType === 'custom'
                                  ? 'bg-indigo-50 dark:bg-indigo-900/30 border-indigo-500 dark:border-indigo-400 text-indigo-700 dark:text-indigo-300 font-medium'
                                  : 'bg-card dark:bg-surface-dark border-border dark:border-border-dark text-text-secondary dark:text-text-secondary-dark hover:bg-surface dark:hover:bg-surface-dark'
                              }`}
                            >
                              Custom Colours
                            </button>
                          </div>
                        </div>

                        {(color.colorType || 'standard') === 'standard' ? (
                          <>
                            <ColorSelector
                              label="Base Color"
                              selectedColor={color.baseColor || 'indigo'}
                              onSelect={(selected) => updateColor(index, 'baseColor', selected)}
                            />
                            <p className="text-xs text-text-muted dark:text-text-muted-dark">Secondary: Auto (complementary)</p>
                          </>
                        ) : (
                          <>
                            <div>
                              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Base Color</label>
                              <div className="flex gap-2 items-center">
                                <input
                                  type="color"
                                  value={color.hexBase || '#4f46e5'}
                                  onChange={(e) => updateColor(index, 'hexBase', e.target.value)}
                                  className="w-16 h-10 rounded-input border border-border dark:border-border-dark cursor-pointer"
                                />
                                <input
                                  type="text"
                                  value={color.hexBase || '#4f46e5'}
                                  onChange={(e) => updateColor(index, 'hexBase', e.target.value)}
                                  placeholder="#4f46e5"
                                  className="flex-1 px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark font-mono text-sm"
                                />
                              </div>
                            </div>

                            <div>
                              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Secondary Color (optional)</label>
                              <div className="flex gap-2 items-center">
                                <input
                                  type="color"
                                  value={color.hexSecondary || color.hexBase || '#7c3aed'}
                                  onChange={(e) => updateColor(index, 'hexSecondary', e.target.value)}
                                  className="w-16 h-10 rounded-input border border-border dark:border-border-dark cursor-pointer"
                                />
                                <input
                                  type="text"
                                  value={color.hexSecondary || ''}
                                  onChange={(e) => updateColor(index, 'hexSecondary', e.target.value || null)}
                                  placeholder="Leave blank for auto (complementary)"
                                  className="flex-1 px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark font-mono text-sm"
                                />
                              </div>
                              <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">Leave blank to use auto (complementary) color</p>
                            </div>
                          </>
                        )}

                        {/* Preview of generated gradient */}
                        <div>
                          <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Preview</label>
                          <div 
                            className="w-full h-16 rounded-container overflow-hidden"
                            style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                          />
                        </div>

                        {/* Collapsible advanced view */}
                        <details className="text-sm">
                          <summary className="cursor-pointer text-text-secondary dark:text-text-muted-dark hover:text-text-primary dark:hover:text-text-primary-dark font-medium mb-2">
                            Advanced: Generated Styles
                          </summary>
                          <div className="bg-card dark:bg-surface-dark p-3 rounded-container border border-border dark:border-border-dark space-y-2 text-xs font-mono">
                            <div><span className="text-text-muted dark:text-text-muted-dark">Gradient Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.gradientStyle || 'N/A'}</span></div>
                            <div><span className="text-text-muted dark:text-text-muted-dark">Button Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.buttonStyle || 'N/A'}</span></div>
                            <div><span className="text-text-muted dark:text-text-muted-dark">Link Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.linkStyle || 'N/A'}</span></div>
                            <div><span className="text-text-muted dark:text-text-muted-dark">Text Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.textStyle || 'N/A'}</span></div>
                          </div>
                        </details>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div 
                            className="w-12 h-12 rounded-full"
                            style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                          />
                          <div>
                            <div className="font-medium text-text-primary dark:text-text-primary-dark">
                              {color.baseColor ? (color.baseColor.charAt(0).toUpperCase() + color.baseColor.slice(1)) : color.name}
                            </div>
                            <div className="text-xs text-text-muted dark:text-text-muted-dark">
                              {color.baseColor ? 'Standard' : 'Custom'} (Secondary: Auto)
                            </div>
                          </div>
                        </div>
                        <button
                          onClick={() => setEditingColorIndex(index)}
                          className="px-3 py-1 text-sm bg-card dark:bg-surface-dark border border-border dark:border-border-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark flex items-center gap-1 text-text-primary dark:text-text-primary-dark"
                        >
                          <Edit3 className="w-3 h-3" /> Edit
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="hidden lg:flex w-1/2 bg-main dark:bg-main-dark items-center justify-center p-10">
        <div className="bg-card dark:bg-card-dark rounded-card p-8 shadow-lg max-w-md w-full border border-border dark:border-border-dark relative z-10 isolate">
          <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Preview</h3>
          <div className="space-y-4">
            <div>
              <div className="text-sm text-text-secondary dark:text-text-muted-dark mb-2">Default Organisation:</div>
              <div className="font-medium text-text-primary dark:text-text-primary-dark">{localSettings.default_organisation || 'Not set'}</div>
            </div>
            <div>
              <div className="text-sm text-text-secondary dark:text-text-muted-dark mb-3">Color Effects:</div>
              {(() => {
                const previewColor = editingColorIndex !== null && localSettings.theme_colors?.[editingColorIndex]
                  ? localSettings.theme_colors[editingColorIndex]
                  : localSettings.theme_colors?.[0];
                
                return (
                  <div className="space-y-3">
                    {/* Text example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Text</div>
                      <div 
                        className="text-lg font-medium"
                        style={{ color: previewColor?.textStyle || '#4f46e5' }}
                      >
                        Example Text
                      </div>
                    </div>
                    
                    {/* Link example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Link</div>
                      <a 
                        href="#" 
                        className="inline-block px-4 py-2 rounded-input border border-border dark:border-border-dark transition-all hover:opacity-80"
                        style={{ color: previewColor?.linkStyle || '#4f46e5' }}
                        onClick={(e) => e.preventDefault()}
                      >
                        Example Link
                      </a>
                    </div>
                    
                    {/* Button example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Button</div>
                      <button 
                        className="px-4 py-2 rounded-full font-medium text-white shadow-md transition-transform active:scale-[0.98]"
                        style={{ backgroundColor: previewColor?.buttonStyle || '#4f46e5' }}
                      >
                        Example Button
                      </button>
                    </div>
                    
                    {/* Gradient background example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Gradient Background</div>
                      <div 
                        className="w-full h-12 rounded-container overflow-hidden"
                        style={{ background: previewColor?.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                      />
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      </div>
      <div className="fixed bottom-4 right-4 z-10 text-center group">
        <div className="flex justify-center">
          <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
          <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
        </div>
      </div>
    </div>
  );
}
