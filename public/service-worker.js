/* global self, caches, fetch */

// Bump when the cached shell format changes so installed workers pick up the new version.
const CACHE_NAME = 'swiish-app-shell-v4';
// Cache the server-rendered '/' response rather than the raw /index.html build file: the server
// adds a per-request CSP nonce header and matching nonces to the inline scripts, so the cached
// body and CSP header must come from the same response.
const APP_SHELL = ['/'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(APP_SHELL);
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) =>
      Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Only handle GET requests
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  const isSameOrigin = url.origin === self.location.origin;
  if (!isSameOrigin) return;

  // Bypass caching for dynamic/API endpoints
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/admin') ||
    url.pathname.startsWith('/manifest/') ||
    url.pathname.startsWith('/icons/') ||
    url.pathname.startsWith('/uploads/')
  ) {
    return;
  }

  const isNavigation =
    request.mode === 'navigate' ||
    (request.headers.get('accept') || '').includes('text/html');

  // Navigations - NETWORK FIRST to avoid stale HTML
  if (isNavigation) {
    event.respondWith(
      // Fetch the page that was actually requested. The server renders every route with a
      // matching CSP nonce and meta tags, so the response must not be swapped for /index.html.
      fetch(request, { cache: 'no-store' })
        .then((resp) => {
          // Don't cache navigations - always fetch fresh to avoid stale content
          // Return the network response directly
          return resp;
        })
        .catch(() => {
          // Only fall back to cache if network completely fails (offline)
          return caches.match('/').then((cached) => {
            if (cached) return cached;
            // Last resort: offline fallback
            return new Response('<!DOCTYPE html><html><body>Offline - Please check your connection</body></html>', {
              headers: { 'Content-Type': 'text/html' },
            });
          });
        })
    );
    return;
  }

  // Cache-first for static assets, but never fall back to index.html (avoid wrong MIME)
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request, { cache: 'no-store' })
          .then((resp) => {
            if (resp.ok) {
              const clone = resp.clone();
              caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
            }
            return resp;
          })
          // If network fails and nothing cached, propagate the failure (no HTML fallback)
          .catch((err) => {
            return cached || Promise.reject(err);
          });
      })
    );
    return;
  }
});


