import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import {
  Settings, RefreshCw, Check, Save, Lock, Sun, Moon, Plus, Users,
  Edit3, Trash2, ExternalLink, User
} from 'lucide-react';
import { API_ENDPOINT } from './constants/app';
import { applyThemeCssVars } from './constants/theme';
import { extractBaseColorFromGradient, getTailwindColorHex, getComplementaryColor } from './constants/colors';
import { getDefaultTemplate } from './utils/cardTemplate';
import Modal from './components/common/Modal';
import VersionBadge from './components/common/VersionBadge';
import DemoModeBanner from './components/common/DemoModeBanner';
import EditorView from './components/editor/EditorView';
import SettingsView from './components/settings/SettingsView';
import UserManagementView from './components/users/UserManagementView';
import InvitationAcceptance from './components/invitations/InvitationAcceptance';
import PublicCardRoute from './components/public-card/PublicCardRoute';

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
  const editInProgressRef = useRef(false);
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
            // After auth check, load the card data — but skip if handleEdit is already
            // in progress (e.g. triggered by the admin clicking the Edit button, which
            // navigates here and would otherwise cause a second fetch without userId)
            if (!editInProgressRef.current) {
              handleEdit(slug);
            }
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
          navigate('/login', { replace: true });
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
          navigate('/people', { replace: true });
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
          navigate('/login', { replace: true });
        }
      });
    } else if (path === '/users') {
      setView('user-management');
      fetchCsrfToken();
      checkAuth().then((authResult) => {
        if (!authResult.isAuthenticated) {
          navigate('/login', { replace: true });
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
            navigate('/people', { replace: true });
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
              navigate('/login', { replace: true });
            }
          }).catch((e) => {
            console.error('Auth check failed:', e);
            navigate('/login', { replace: true });
          });
          return;
        }

        // Normal mode: continue with regular auth flow
        // (status already checked above, setupComplete must be true to get here)
        if (status === null) {
          // If check failed (server not running, network error, etc.), default to setup wizard
          navigate('/setup', { replace: true });
          document.title = "Initial Setup";
        } else if (!status.setupComplete || status.userCount === 0) {
          // Setup not complete or no users exist, show setup wizard
          navigate('/setup', { replace: true });
          document.title = "Initial Setup";
        } else {
          // Setup complete, check authentication
          if (path === '/' || path === '/admin') {
            // Redirect root/admin to /people (explicit redirect)
            navigate('/people', { replace: true });
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
                  navigate(`/people/edit/${firstCard.slug}`, { replace: true });
                }
              } else {
                // Owner - show dashboard
                setView('admin-dashboard');
              }
          document.title = "Admin Dashboard";
            } else {
              // Not authenticated, redirect to login (explicit redirect)
              navigate('/login', { replace: true });
            }
          }).catch((e) => {
            console.error('Auth check failed:', e);
            navigate('/login', { replace: true });
          });
        }
      }).catch((e) => {
        // If promise rejects, default to setup wizard
        console.error('Setup status check failed:', e);
        navigate('/setup', { replace: true });
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
          if (userData.role === 'member') {
            fetchPublicSettings(userData.orgSlug || 'default');
          } else {
            fetchSettings();
          }

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
        `Are you sure you want to permanently delete ${userEmail}? This will delete the user and all their cards. This action cannot be undone.`,
        async () => {
          try {
            const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
              method: 'DELETE'
            });
            if (res.ok) {
              if (showAlert) showAlert('User deleted successfully', 'success');
              checkAuth(); // Refresh card list
            } else {
              const errorData = await res.json().catch(() => ({}));
              if (showAlert) showAlert(errorData.error || 'Failed to delete user', 'error');
            }
          } catch (e) {
            if (showAlert) showAlert('Error deleting user', 'error');
          }
        },
        'Delete User',
        'Delete',
        'Cancel'
      );
    }
  };

  const handleEdit = async (slug, userId) => {
    editInProgressRef.current = true;
    try {
      // User IDs are UUID strings (crypto.randomUUID()). Guard against null/undefined/non-string values.
      const validUserId = userId && typeof userId === 'string' && userId.trim() ? userId : null;
      const isOtherUser = validUserId !== null && validUserId !== currentUserId;
      const fetchUrl = isOtherUser
        ? `${API_ENDPOINT}/admin/cards/${validUserId}/${slug}`
        : `${API_ENDPOINT}/cards/${slug}`;
      const res = await apiCall(fetchUrl);
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
        // Track the owner so handleSave sends it to the correct user's card
        if (isOtherUser) {
          setTargetUserIdForNewCard(validUserId);
        } else {
          setTargetUserIdForNewCard(null);
        }
        setCurrentSlug(slug);
        setView('admin-editor');
        // Navigate to editor route only if not already there
        if (location.pathname !== `/people/edit/${slug}`) {
          navigate(`/people/edit/${slug}`);
        }
      } else {
        let errorMsg = 'Failed to load card';
        try {
          const errData = await res.json();
          errorMsg = errData.error || errorMsg;
        } catch {}
        showAlert(`${errorMsg} (${res.status})`, 'error');
      }
    } finally {
      editInProgressRef.current = false;
    }
  };

  const handleDelete = async (slug, userId) => {
    showConfirm(
      `Are you sure you want to delete ${slug}?`,
      async () => {
        const validUserId = userId && typeof userId === 'string' && userId.trim() ? userId : null;
        const isOtherUser = validUserId !== null && validUserId !== currentUserId;
        const deleteUrl = isOtherUser
          ? `${API_ENDPOINT}/cards/${slug}?userId=${encodeURIComponent(validUserId)}`
          : `${API_ENDPOINT}/cards/${slug}`;
        const res = await apiCall(deleteUrl, {
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
            <div className="columns-1 md:columns-2 lg:columns-3 gap-6">
              {groupCardsByUser(cardList).map(user => {
                // Filter out entries without slugs (these represent users without cards)
                const userCards = user.cards.filter(c => c.slug);
                const userKey = user.userId || user.userEmail || 'unknown';

                return (
                  <div key={userKey} className="bg-card dark:bg-card-dark rounded-card shadow-sm border border-border-subtle dark:border-border-dark hover:shadow-md transition-shadow flex flex-col p-[15px] h-fit break-inside-avoid mb-6">
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
                                   <button onClick={(e) => { e.stopPropagation(); handleDelete(card.slug, card.userId); }} className="absolute top-0 right-0 p-2 text-text-muted-subtle dark:text-text-muted-dark hover:text-error-text dark:hover:text-error-text-dark hover:bg-error-bg dark:hover:bg-error-bg-dark rounded-full transition-colors">
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
                                   <button onClick={() => handleEdit(card.slug, card.userId)} className="flex-1 py-2 text-xs font-medium text-confirm-text dark:text-confirm-text-dark bg-confirm dark:bg-confirm-dark rounded-button hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark flex items-center justify-center gap-1"><Edit3 className="w-3 h-3"/> Edit</button>
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
                        <div className="bg-surface dark:bg-surface-dark/50 rounded-t-badge rounded-b-container p-5 border border-border dark:border-border-dark" style={{ aspectRatio: '1.586 / 1' }}>
                          <div className="w-full h-full bg-surface dark:bg-surface-dark/30 rounded-t-badge rounded-b-badge border-thick border-dashed border-border dark:border-border-dark flex flex-col items-center justify-center">
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
            onLogout={userRole === 'member' ? handleLogout : undefined}
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
      <DemoModeBanner isDemoMode={isDemoMode} demoResetInterval={demoResetInterval} />
      <Routes>
        {/* Admin routes - must come before public routes to prevent matching */}
        <Route path="/login" element={renderAdminViews()} />
        <Route path="/setup" element={renderAdminViews()} />
        <Route path="/people/edit/:slug" element={renderAdminViews()} />
        <Route path="/people" element={renderAdminViews()} />
        <Route path="/settings" element={renderAdminViews()} />
        <Route path="/users" element={renderAdminViews()} />
        <Route path="/cards" element={renderAdminViews()} />
        <Route path="/" element={renderAdminViews()} />
        {/* Invitation acceptance route - must come before public card routes */}
        <Route path="/invite/:token" element={
          <InvitationAcceptance
            apiCall={apiCall}
            showAlert={showAlert}
            API_ENDPOINT={API_ENDPOINT}
          />
        } />
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
