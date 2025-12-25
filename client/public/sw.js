/* eslint-disable no-restricted-globals */

// TrustMarket Service Worker for PWA functionality
const CACHE_VERSION = '1.0.1';
const STATIC_CACHE = `trustmarket-static-v${CACHE_VERSION}`;
const DYNAMIC_CACHE = `trustmarket-dynamic-v${CACHE_VERSION}`;
const IMAGE_CACHE = `trustmarket-images-v${CACHE_VERSION}`;
const API_CACHE = `trustmarket-api-v${CACHE_VERSION}`;

// Cache quotas (in bytes)
const MAX_STATIC_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_DYNAMIC_SIZE = 20 * 1024 * 1024; // 20MB
const MAX_IMAGE_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_API_SIZE = 10 * 1024 * 1024; // 10MB

// Assets to cache immediately on install
const STATIC_ASSETS = [
  '/',
  '/manifest.json',
  '/favicon.ico',
  '/icons/icon-72.png',
  '/icons/icon-96.png',
  '/icons/icon-128.png',
  '/icons/icon-144.png',
  '/icons/icon-152.png',
  '/icons/icon-192.png',
  '/icons/icon-384.png',
  '/icons/icon-512.png',
  '/og-image.jpg',
];

// API endpoints that should be cached with network-first strategy
const API_CACHE_PATTERNS = [
  /\/api\/categories/,
  /\/api\/featured/,
  /\/api\/trending/,
];

// API endpoints that should use stale-while-revalidate
const STALE_PATTERNS = [
  /\/api\/listings\?.*page=1/,
  /\/api\/search\?.*page=1/,
];

// Navigation preload setup
self.addEventListener('install', (event) => {
  console.log('[SW] Installing service worker...');
  
  event.waitUntil(
    Promise.all([
      caches.open(STATIC_CACHE).then((cache) => {
        console.log('[SW] Caching static assets');
        return cache.addAll(STATIC_ASSETS.map(url => {
          return new Request(url, { cache: 'reload' });
        }));
      }),
      // Enable navigation preload if supported
      self.registration.navigationPreload.enable()
    ])
    .then(() => {
      console.log('[SW] Static assets cached successfully');
      return self.skipWaiting();
    })
    .catch((error) => {
      console.error('[SW] Failed to cache static assets:', error);
    })
  );
});

// Clean up old caches and activate
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating service worker...');
  
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          // Delete caches that don't match current version
          if (cacheName !== STATIC_CACHE && 
              cacheName !== DYNAMIC_CACHE && 
              cacheName !== IMAGE_CACHE &&
              cacheName !== API_CACHE) {
            console.log('[SW] Deleting obsolete cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
    .then(() => {
      console.log('[SW] Service worker activated');
      // Take control of all clients immediately
      return self.clients.claim();
    })
  );
});

// Fetch event with advanced caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Skip chrome-extension and other non-http(s) requests
  if (!url.protocol.startsWith('http')) {
    return;
  }
  
  // Handle different types of requests with appropriate strategies
  if (isStaticAsset(request.url)) {
    event.respondWith(cacheFirst(request, STATIC_CACHE));
  } else if (isAPIRequest(request.url)) {
    event.respondWith(networkFirst(request, API_CACHE, STALE_PATTERNS.some(p => p.test(request.url))));
  } else if (isImageRequest(request.url)) {
    event.respondWith(cacheFirst(request, IMAGE_CACHE, true));
  } else if (isNavigationRequest(request)) {
    event.respondWith(handleNavigation(request));
  } else {
    event.respondWith(staleWhileRevalidate(request, DYNAMIC_CACHE));
  }
});

// Navigation preload handler
self.addEventListener('fetch', (event) => {
  if (event.request.mode === 'navigate') {
    event.respondWith(
      Promise.all([
        self.registration.navigationPreload.getState(),
        event.preloadResponse.then((response) => {
          if (response) {
            return response;
          }
          return fetch(event.request);
        })
      ]).then(([state, response]) => {
        // Clone and cache the response
        const clonedResponse = response.clone();
        caches.open(DYNAMIC_CACHE).then((cache) => {
          cache.put(event.request, clonedResponse);
        });
        return response;
      }).catch(() => {
        return caches.match('/');
      })
    );
  }
});

// Background sync for offline actions
self.addEventListener('sync', (event) => {
  console.log('[SW] Background sync:', event.tag);
  
  if (event.tag === 'background-sync-listings') {
    event.waitUntil(syncListings());
  } else if (event.tag === 'background-sync-messages') {
    event.waitUntil(syncMessages());
  } else if (event.tag.startsWith('sync-')) {
    event.waitUntil(syncGeneric(event.tag));
  }
});

// Push notifications handler
self.addEventListener('push', (event) => {
  console.log('[SW] Push received:', event);
  
  if (!event.data) {
    return;
  }
  
  const data = event.data.json();
  const options = {
    body: data.body,
    icon: '/icons/icon-192.png',
    badge: '/icons/badge-72.png',
    image: data.image,
    vibrate: [200, 100, 200],
    data: data.data,
    actions: data.actions || [
      { action: 'view', title: 'View' },
      { action: 'dismiss', title: 'Dismiss' }
    ],
    requireInteraction: data.requireInteraction || false,
    silent: data.silent || false,
    tag: data.tag || 'trustmarket-notification',
    renotify: true
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  console.log('[SW] Notification click:', event);
  
  event.notification.close();
  
  const { action, data } = event;
  let url = '/';
  
  if (action === 'dismiss') {
    return;
  }
  
  if (action === 'view_listing' && data.listingId) {
    url = `/listing/${data.listingId}`;
  } else if (action === 'view_message' && data.conversationId) {
    url = `/messages/${data.conversationId}`;
  } else if (action === 'view_profile' && data.userId) {
    url = `/profile/${data.userId}`;
  } else if (data && data.url) {
    url = data.url;
  }
  
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        // Try to focus an existing window
        for (const client of clientList) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }
        // Open a new window if no existing window found
        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
  );
});

// Message handler for communication with main thread
self.addEventListener('message', (event) => {
  console.log('[SW] Message received:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'CACHE_URLS') {
    const { urls } = event.data;
    event.waitUntil(
      caches.open(DYNAMIC_CACHE)
        .then((cache) => {
          return cache.addAll(urls);
        })
        .then(() => {
          event.ports[0].postMessage({ success: true });
        })
        .catch((error) => {
          event.ports[0].postMessage({ success: false, error: error.message });
        })
    );
  }
  
  if (event.data && event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then((cacheNames) => {
        return Promise.all(cacheNames.map((cacheName) => caches.delete(cacheName)));
      })
    );
  }
  
  if (event.data && event.data.type === 'GET_CACHE_SIZE') {
    event.waitUntil(
      getCacheSize().then((size) => {
        event.ports[0].postMessage({ size });
      })
    );
  }
});

// Cache strategies implementation
async function cacheFirst(request, cacheName, manageQuota = false) {
  const cachedResponse = await caches.match(request);
  
  if (cachedResponse) {
    // Refresh cache in background for stale-while-revalidate behavior
    fetchAndCache(request, cacheName).catch(() => {});
    return cachedResponse;
  }
  
  return fetchAndCache(request, cacheName, manageQuota);
}

async function networkFirst(request, cacheName, allowStale = false) {
  try {
    const response = await fetch(request);
    
    if (response.ok) {
      const clonedResponse = response.clone();
      fetchAndCache(request, cacheName, clonedResponse).catch(() => {});
    }
    
    return response;
  } catch (error) {
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Return offline fallback for navigation requests
    if (isNavigationRequest(request)) {
      return caches.match('/');
    }
    
    throw error;
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cachedResponse = await caches.match(request);
  
  const fetchPromise = fetchAndCache(request, cacheName).catch(() => {});
  
  return cachedResponse || fetchPromise;
}

async function handleNavigation(request) {
  try {
    const preloadResponse = await event.preloadResponse;
    if (preloadResponse) {
      return preloadResponse;
    }
    
    const response = await fetch(request);
    const clonedResponse = response.clone();
    caches.open(DYNAMIC_CACHE).then((cache) => {
      cache.put(request, clonedResponse);
    });
    return response;
  } catch (error) {
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }
    return caches.match('/');
  }
}

// Helper functions
async function fetchAndCache(request, cacheName, response) {
  const res = response || await fetch(request);
  
  if (res.ok) {
    const cache = await caches.open(cacheName);
    cache.put(request, res.clone());
    
    // Manage cache quota
    if (cacheName === IMAGE_CACHE) {
      manageCacheQuota(IMAGE_CACHE, MAX_IMAGE_SIZE);
    } else if (cacheName === DYNAMIC_CACHE) {
      manageCacheQuota(DYNAMIC_CACHE, MAX_DYNAMIC_SIZE);
    } else if (cacheName === API_CACHE) {
      manageCacheQuota(API_CACHE, MAX_API_SIZE);
    }
  }
  
  return res;
}

async function manageCacheQuota(cacheName, maxSize) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  let totalSize = 0;
  
  // Calculate total cache size
  for (const request of keys) {
    const response = await cache.match(request);
    const blob = await response.blob();
    totalSize += blob.size;
  }
  
  // If over quota, remove oldest entries
  if (totalSize > maxSize) {
    const entriesToDelete = Math.floor(keys.length * 0.2); // Delete 20% oldest
    for (let i = 0; i < entriesToDelete; i++) {
      await cache.delete(keys[i]);
    }
    console.log(`[SW] Cleared ${entriesToDelete} entries from ${cacheName}`);
  }
}

async function getCacheSize() {
  let totalSize = 0;
  const cacheNames = await caches.keys();
  
  for (const cacheName of cacheNames) {
    const cache = await caches.open(cacheName);
    const keys = await cache.keys();
    
    for (const request of keys) {
      const response = await cache.match(request);
      const blob = await response.blob();
      totalSize += blob.size;
    }
  }
  
  return totalSize;
}

function isStaticAsset(url) {
  return url.includes('/static/') || 
         url.includes('/icons/') || 
         url.includes('/images/') ||
         url.includes('/fonts/') ||
         url.endsWith('.css') ||
         url.endsWith('.js') ||
         url.endsWith('.map') ||
         url.endsWith('.ico');
}

function isAPIRequest(url) {
  return url.includes('/api/') && API_CACHE_PATTERNS.some(pattern => pattern.test(url));
}

function isImageRequest(url) {
  return url.includes('cloudinary.com') || 
         url.includes('/images/') ||
         url.includes('/uploads/') ||
         url.match(/\.(jpg|jpeg|png|gif|webp|svg|avif|webm)$/i);
}

function isNavigationRequest(request) {
  return request.mode === 'navigate';
}

// Background sync implementations
async function syncListings() {
  console.log('[SW] Syncing pending listings...');
  
  try {
    // Open IndexedDB to get pending listings
    const db = await openDB();
    const pendingListings = await getPendingItems(db, 'pendingListings');
    
    for (const listing of pendingListings) {
      try {
        await fetch('/api/listings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${listing.token}`
          },
          body: JSON.stringify(listing.data)
        });
        
        // Remove from pending
        await removePendingItem(db, 'pendingListings', listing.id);
        
        // Notify the client
        const clients = await self.clients.matchAll();
        clients.forEach(client => {
          client.postMessage({
            type: 'SYNC_COMPLETE',
            message: 'Listing uploaded successfully'
          });
        });
      } catch (error) {
        console.error('[SW] Failed to sync listing:', error);
      }
    }
  } catch (error) {
    console.error('[SW] Sync listings error:', error);
  }
}

async function syncMessages() {
  console.log('[SW] Syncing pending messages...');
  
  try {
    const db = await openDB();
    const pendingMessages = await getPendingItems(db, 'pendingMessages');
    
    for (const message of pendingMessages) {
      try {
        await fetch('/api/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${message.token}`
          },
          body: JSON.stringify(message.data)
        });
        
        await removePendingItem(db, 'pendingMessages', message.id);
      } catch (error) {
        console.error('[SW] Failed to sync message:', error);
      }
    }
  } catch (error) {
    console.error('[SW] Sync messages error:', error);
  }
}

async function syncGeneric(tag) {
  console.log('[SW] Syncing generic:', tag);
  
  // Generic sync handler for other pending actions
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({
      type: 'SYNC_COMPLETE',
      message: 'Data synchronized'
    });
  });
}

// IndexedDB helper functions
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('TrustMarketSW', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      if (!db.objectStoreNames.contains('pendingListings')) {
        db.createObjectStore('pendingListings', { keyPath: 'id', autoIncrement: true });
      }
      
      if (!db.objectStoreNames.contains('pendingMessages')) {
        db.createObjectStore('pendingMessages', { keyPath: 'id', autoIncrement: true });
      }
    };
  });
}

function getPendingItems(db, storeName) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readonly');
    const store = transaction.objectStore(storeName);
    const request = store.getAll();
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

function removePendingItem(db, storeName, id) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = store.delete(id);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

console.log('[SW] TrustMarket service worker loaded - Version', CACHE_VERSION);
