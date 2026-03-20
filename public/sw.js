/*
 * Service Worker — Business Quotes App
 * Provides offline capability and caching for the PWA.
 *
 * HOW IT WORKS:
 * 1. On install, it caches the core app files
 * 2. On fetch, it serves cached files first, then falls back to network
 * 3. To update the app, change the CACHE_VERSION below — this forces
 *    the old cache to be deleted and new files to be downloaded
 */

const CACHE_VERSION = "bq-v1";
const CORE_ASSETS = ["/", "/index.html"];

// Install — cache core assets
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(CORE_ASSETS))
  );
  // Activate immediately without waiting for old tabs to close
  self.skipWaiting();
});

// Activate — delete old caches when a new version is deployed
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_VERSION)
          .map((key) => caches.delete(key))
      )
    )
  );
  // Take control of all open tabs immediately
  self.clients.claim();
});

// Fetch — serve from cache first, fall back to network
self.addEventListener("fetch", (event) => {
  // Only handle GET requests
  if (event.request.method !== "GET") return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        // Cache successful responses for future offline use
        if (response.ok && response.type === "basic") {
          const clone = response.clone();
          caches.open(CACHE_VERSION).then((cache) => {
            cache.put(event.request, clone);
          });
        }
        return response;
      });
    })
  );
});
