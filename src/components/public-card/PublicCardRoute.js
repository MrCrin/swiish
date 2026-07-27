import React, { useEffect, useRef } from 'react';
import { useParams, useLocation } from 'react-router-dom';
import { applyThemeCssVars } from '../../constants/theme';
import CardDisplay from './CardDisplay';

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

export default PublicCardRoute;
