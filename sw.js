const V = "f0nd-shell-v1";
const key = (u, nav) => nav ? new Request(u.origin + u.pathname) : new Request(u.origin + u.pathname + u.search);
self.addEventListener("install", () => { self.skipWaiting(); });
self.addEventListener("activate", e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.indexOf("f0nd-shell-") === 0 && k !== V) await caches.delete(k);
    await self.clients.claim();
  })());
});
self.addEventListener("fetch", e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== "GET" || u.origin !== location.origin || u.pathname === "/sw.js") return;
  const nav = r.mode === "navigate";
  e.respondWith((async () => {
    const c = await caches.open(V);
    try {
      const n = await fetch(r);
      if (n && n.ok && (nav || /\.(png|ico|webp|svg|jpg|css|js|json)$/.test(u.pathname))) c.put(key(u, nav), n.clone());
      return n;
    } catch (err) {
      const h = await c.match(key(u, nav));
      if (h) return h;
      throw err;
    }
  })());
});
