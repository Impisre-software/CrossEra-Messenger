const CACHE = 'crossera-v1';
const ASSETS = ['/', '/index.php'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).catch(()=>{}));
    self.skipWaiting();
});

self.addEventListener('activate', e => {
    e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
    self.clients.claim();
});

self.addEventListener('fetch', e => {
    const url = new URL(e.request.url);
    if (e.request.method !== 'GET') return;
    if (url.pathname.match(/\.(png|jpg|jpeg|gif|css|js|woff2?)$/)) {
        e.respondWith(
            caches.match(e.request).then(r => r || fetch(e.request).then(resp => {
                const copy = resp.clone();
                caches.open(CACHE).then(c => c.put(e.request, copy)).catch(()=>{});
                return resp;
            }).catch(() => caches.match('/')))
        );
    }
});
