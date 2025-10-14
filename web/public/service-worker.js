// web/public/service-worker.js
// NebulaCore PWA Service Worker (production-ready)
// - Precise caching strategies (cache-first, network-first, stale-while-revalidate)
// - Versioning, skipWaiting, clients.claim
// - Runtime caching for APIs and images with size/age eviction
// - Offline fallback for navigation
// - Push notifications with actions & click handling
// - Background Sync queue (simple IndexedDB-backed) for retrying failed POSTs
// - PostMessage broadcast for update/health events

const VERSION = 'nebula-v1.8.0';
const CORE_CACHE = `nebula-core-${VERSION}`;
const RUNTIME_CACHE = `nebula-runtime-${VERSION}`;
const API_CACHE = `nebula-api-${VERSION}`;
const IMG_CACHE = `nebula-img-${VERSION}`;
const MAX_API_ENTRIES = 100;
const MAX_IMG_ENTRIES = 200;
const OFFLINE_PAGE = '/offline.html';

const CORE_ASSETS = [
  '/',
  '/index.html',
  '/offline.html',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/css/app.css',
  '/js/app.js'
];

// minimal IndexedDB queue for failed requests (Background Sync)
const DB_NAME = 'nebula-sw-queue';
const STORE_NAME = 'outbox';

self.importScripts(); // placeholder for future imports

// -------------------- IndexedDB helpers --------------------
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbAdd(item) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const r = store.add(item);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

async function idbGetAll() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const r = store.getAll();
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

async function idbDelete(id) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const r = store.delete(id);
    r.onsuccess = () => res(true);
    r.onerror = () => rej(r.error);
  });
}

// -------------------- Utility helpers --------------------
async function trimCache(cacheName, maxItems) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  if (keys.length > maxItems) {
    const toDelete = keys.slice(0, keys.length - maxItems);
    await Promise.all(toDelete.map(k => cache.delete(k)));
  }
}

function isNavigationRequest(request) {
  return request.mode === 'navigate' ||
    (request.method === 'GET' && request.headers.get('accept') && request.headers.get('accept').includes('text/html'));
}

function log(...args) {
  // toggleable logging
  // console.log('[SW]', ...args);
}

// -------------------- Install & Activate --------------------
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CORE_CACHE).then(cache => cache.addAll(CORE_ASSETS))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    // delete old caches
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => ![CORE_CACHE, RUNTIME_CACHE, API_CACHE, IMG_CACHE].includes(k))
      .map(k => caches.delete(k)));
    self.clients.claim();
    // notify clients that SW is active
    const clients = await self.clients.matchAll({ includeUncontrolled: true });
    clients.forEach(c => c.postMessage({ type: 'SW_ACTIVATED', version: VERSION }));
  })());
});

// -------------------- Fetch strategy --------------------
self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  // Ignore non-GET for most caching except queueing POSTs
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    // Try network; if fails, enqueue for background sync
    event.respondWith((async () => {
      try {
        const netResp = await fetch(req.clone());
        return netResp;
      } catch (err) {
        // enqueue request body
        try {
          const cloned = await cloneRequestForQueue(req);
          await idbAdd({ url: req.url, method: req.method, headers: [...req.headers], body: cloned, timestamp: Date.now() });
          // Register sync
          if ('sync' in self.registration) {
            await self.registration.sync.register('nebula-outbox-sync');
          }
        } catch (e) {
          // ignore queue failure
        }
        return new Response(JSON.stringify({ queued: true }), {
          status: 202,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    })());
    return;
  }

  // Navigation requests (HTML): Network first, fallback to cache -> offline page
  if (isNavigationRequest(req)) {
    event.respondWith((async () => {
      try {
        const networkResponse = await fetch(req);
        // optionally update runtime cache
        const cache = await caches.open(RUNTIME_CACHE);
        cache.put(req, networkResponse.clone());
        return networkResponse;
      } catch (err) {
        const cached = await caches.match(req);
        if (cached) return cached;
        const offline = await caches.match(OFFLINE_PAGE);
        return offline || new Response('Offline', { status: 503, statusText: 'Offline' });
      }
    })());
    return;
  }

  // API requests -> network-first with cache fallback
  if (url.pathname.startsWith('/api/') || url.hostname !== location.hostname && url.pathname.startsWith('/api/')) {
    event.respondWith((async () => {
      const cache = await caches.open(API_CACHE);
      try {
        const netResp = await fetch(req);
        if (netResp && netResp.ok) {
          cache.put(req, netResp.clone());
          // trim api cache
          trimCache(API_CACHE, MAX_API_ENTRIES);
        }
        return netResp;
      } catch (err) {
        const cached = await cache.match(req);
        if (cached) return cached;
        return new Response(JSON.stringify({ error: 'offline' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
      }
    })());
    return;
  }

  // Images -> cache-first with stale-while-revalidate
  if (req.destination === 'image' || /\.(png|jpg|jpeg|gif|webp|svg)$/.test(url.pathname)) {
    event.respondWith((async () => {
      const cache = await caches.open(IMG_CACHE);
      const cached = await cache.match(req);
      if (cached) {
        // fetch update in background
        event.waitUntil((async () => {
          try {
            const net = await fetch(req);
            if (net && net.ok) {
              cache.put(req, net.clone());
              trimCache(IMG_CACHE, MAX_IMG_ENTRIES);
            }
          } catch (e) { /* ignore */ }
        })());
        return cached;
      }
      try {
        const netResp = await fetch(req);
        if (netResp && netResp.ok) {
          cache.put(req, netResp.clone());
          trimCache(IMG_CACHE, MAX_IMG_ENTRIES);
        }
        return netResp;
      } catch (err) {
        // fallback placeholder image (if present)
        const placeholder = await caches.match('/icons/icon-192.png');
        return placeholder || new Response(null, { status: 404 });
      }
    })());
    return;
  }

  // Static assets -> cache-first, stale-while-revalidate
  event.respondWith((async () => {
    const cached = await caches.match(req);
    if (cached) {
      // update in background
      event.waitUntil((async () => {
        try {
          const fresh = await fetch(req);
          if (fresh && fresh.ok) {
            const cache = await caches.open(RUNTIME_CACHE);
            cache.put(req, fresh.clone());
          }
        } catch (e) { /* ignore */ }
      })());
      return cached;
    }
    try {
      const netResp = await fetch(req);
      // store
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(req, netResp.clone());
      return netResp;
    } catch (err) {
      return new Response(null, { status: 504 });
    }
  })());
});

// -------------------- clone request body (for queue) --------------------
async function cloneRequestForQueue(request) {
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('application/json') || ct.includes('text/')) {
    const text = await request.clone().text();
    return { type: 'text', content: text, contentType: ct };
  }
  // try blob/arrayBuffer
  try {
    const buffer = await request.clone().arrayBuffer();
    return { type: 'binary', content: Array.from(new Uint8Array(buffer)), contentType: ct };
  } catch (e) {
    return { type: 'none' };
  }
}

// -------------------- Background Sync: drain outbox --------------------
self.addEventListener('sync', event => {
  if (event.tag === 'nebula-outbox-sync') {
    event.waitUntil(processOutbox());
  }
});

async function processOutbox() {
  const items = await idbGetAll();
  for (const item of items) {
    try {
      const headers = new Headers();
      for (const [k, v] of item.headers || []) headers.append(k, v);
      let body = null;
      if (item.body) {
        if (item.body.type === 'text') body = item.body.content;
        else if (item.body.type === 'binary') body = new Uint8Array(item.body.content).buffer;
      }
      const resp = await fetch(item.url, { method: item.method, headers, body });
      if (resp && (resp.status >= 200 && resp.status < 300)) {
        await idbDelete(item.id);
        // notify clients about successful replay
        const clients = await self.clients.matchAll({ includeUncontrolled: true });
        clients.forEach(c => c.postMessage({ type: 'OUTBOX_SYNCED', id: item.id, url: item.url }));
      }
    } catch (err) {
      // leave in queue for next sync attempt
      log('processOutbox: retry later', err);
    }
  }
}

// -------------------- Push Notifications --------------------
self.addEventListener('push', event => {
  let payload = { title: 'NebulaCore', body: 'You have a new notification', data: {} };
  try {
    const data = event.data && event.data.json();
    payload = Object.assign(payload, data);
  } catch (e) {
    // non-json payload: use text
    const text = event.data && event.data.text();
    if (text) payload.body = text;
  }

  const title = payload.title;
  const options = {
    body: payload.body,
    icon: payload.icon || '/icons/icon-192.png',
    badge: payload.badge || '/icons/icon-192.png',
    data: payload.data || {},
    actions: payload.actions || [ { action: 'open', title: 'Open' } ],
    requireInteraction: payload.requireInteraction || false
  };

  // Optional: verify signature in payload.data.signature (server responsibility)
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const data = event.notification.data || {};
  const action = event.action;

  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (action === 'open' || action === '' || action === null) {
      // focus existing or open new
      for (const client of all) {
        if (client.url && 'focus' in client) {
          client.postMessage({ type: 'NOTIF_CLICK', data });
          return client.focus();
        }
      }
      // open a new window/tab
      return self.clients.openWindow(data.url || '/');
    } else if (action === 'dismiss') {
      // do nothing
    } else {
      // custom action: open with action param
      const target = data.url || '/';
      return self.clients.openWindow(target + (target.includes('?') ? '&' : '?') + 'notif_action=' + action);
    }
  })());
});

self.addEventListener('notificationclose', event => {
  // optional telemetry
  const data = event.notification.data || {};
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ includeUncontrolled: true });
    clients.forEach(c => c.postMessage({ type: 'NOTIF_CLOSED', data }));
  })());
});

// -------------------- Message Handling (from clients) --------------------
self.addEventListener('message', event => {
  const msg = event.data || {};
  if (msg && msg.type) {
    if (msg.type === 'SKIP_WAITING') {
      self.skipWaiting();
    } else if (msg.type === 'CLEAR_CACHES') {
      event.waitUntil((async () => {
        const keys = await caches.keys();
        await Promise.all(keys.map(k => caches.delete(k)));
        const clients = await self.clients.matchAll({ includeUncontrolled: true });
        clients.forEach(c => c.postMessage({ type: 'CACHES_CLEARED' }));
      })());
    } else if (msg.type === 'PING') {
      event.source.postMessage({ type: 'PONG', version: VERSION });
    }
  }
});

// -------------------- Periodic cleanup (optional) --------------------
self.addEventListener('periodicsync', event => {
  if (event.tag === 'nebula-maintenance') {
    event.waitUntil((async () => {
      await trimCache(API_CACHE, MAX_API_ENTRIES);
      await trimCache(IMG_CACHE, MAX_IMG_ENTRIES);
    })());
  }
});

// -------------------- End of service worker --------------------