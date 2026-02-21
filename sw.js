/* WaveChat Service Worker — handles background push notifications */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', event => {
  let data = {};
  try { data = event.data.json(); } catch(e) { data = {title:'WaveChat', body: event.data?.text() || 'New message'} }

  const title = data.title || 'WaveChat';
  const options = {
    body: data.body || '',
    icon: '/icon.png',
    badge: '/badge.png',
    tag: 'wavechat-' + (data.from_id || '0'),
    renotify: true,
    data: { from_id: data.from_id, from_name: data.from_name }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(list => {
      for (const client of list) {
        if ('focus' in client) { client.focus(); return; }
      }
      clients.openWindow('/');
    })
  );
});