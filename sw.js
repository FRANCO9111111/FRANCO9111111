// Our Class Room service worker. Caches the app shell only.
// Supabase/API traffic, auth tokens and attendance data are never cached.
const V = 'ocr-shell-v1';
const SHELL = ['./', './index.html', './admin.html', './manifest.webmanifest',
  './icons/icon-96.png', './icons/icon-192.png', './icons/icon-512.png', './icons/apple-touch-icon.png', './icons/favicon-32.png'];
const CDN_OK = ['cdn.jsdelivr.net', 'fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => Promise.all(SHELL.map(u => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET') return;
  if (u.hostname.endsWith('supabase.co') || u.hostname.endsWith('supabase.in')) return; // never cache data/auth
  if (r.mode === 'navigate') {
    e.respondWith(fetch(r).then(res => { if (res.ok) { const c = res.clone(); caches.open(V).then(ch => ch.put(r, c)); } return res; })
      .catch(() => caches.match(r, { ignoreSearch: true }).then(m => m || caches.match('./index.html'))));
    return;
  }
  if (u.origin === location.origin || CDN_OK.includes(u.hostname)) {
    e.respondWith(caches.match(r).then(hit => {
      const net = fetch(r).then(res => { if (res.ok) { const c = res.clone(); caches.open(V).then(ch => ch.put(r, c)); } return res; }).catch(() => hit);
      return hit || net;
    }));
  }
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => cs.length ? cs[0].focus() : self.clients.openWindow('./index.html')));
});
