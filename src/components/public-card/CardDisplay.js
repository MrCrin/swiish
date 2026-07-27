import React, { useState, useEffect } from 'react';
import {
  Share2, Sun, Moon, Download, Save, Eye, Mail, Phone, MessageCircle,
  Globe, Linkedin, Twitter, Instagram, Github, User, Briefcase, MapPin,
  ExternalLink, Link as LinkIcon
} from 'lucide-react';
import { API_ENDPOINT } from '../../constants/app';
import { ICON_MAP } from '../../constants/icons';
import { applyThemeCssVars } from '../../constants/theme';
import { getThemeGradient, getButtonColor, getLinkColor, getTextColor, darkenHex } from '../../constants/colors';
import { sanitizeText, sanitizeHTML } from '../../utils/sanitize';
import { buildQrPayload, saveQrPayloadToStorage, loadQrPayloadFromStorage } from '../../utils/qr';
import SocialIcon from '../common/SocialIcon';

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

export default CardDisplay;
