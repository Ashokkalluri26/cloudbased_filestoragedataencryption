/**
 * SecureCloud Service Worker
 * Provides offline support, background sync, and PWA functionality
 */

const CACHE_NAME = 'securecloud-v1.0.0';
const STATIC_CACHE = 'securecloud-static-v1';
const DYNAMIC_CACHE = 'securecloud-dynamic-v1';

// Files to cache for offline functionality
const STATIC_FILES = [
    '/',
    '/static/css/style.css',
    '/static/js/main.js',
    '/static/js/crypto.js',
    '/static/js/webauthn.js',
    '/static/manifest.json',
    'https://cdn.tailwindcss.com/3.3.0',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    'https://cdn.socket.io/4.7.2/socket.io.min.js'
];

// API endpoints that should work offline
const OFFLINE_FALLBACK_PAGES = [
    '/dashboard',
    '/profile',
    '/settings'
];

// Install event - cache static files
self.addEventListener('install', event => {
    console.log('Service Worker installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('Caching static files');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('Static files cached successfully');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('Failed to cache static files:', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
    console.log('Service Worker activating...');
    
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('Service Worker activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - serve cached content when offline
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Skip non-GET requests and external URLs
    if (request.method !== 'GET' || !url.origin.includes(self.location.origin)) {
        return;
    }
    
    // Handle different types of requests
    if (request.url.includes('/api/')) {
        event.respondWith(handleApiRequest(request));
    } else if (request.url.includes('/static/')) {
        event.respondWith(handleStaticRequest(request));
    } else {
        event.respondWith(handlePageRequest(request));
    }
});

// Handle API requests with offline fallback
async function handleApiRequest(request) {
    try {
        // Try network first for API requests
        const networkResponse = await fetch(request);
        
        // Cache successful responses
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.log('Network failed for API request, trying cache:', request.url);
        
        // Try to serve from cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Return offline fallback for specific API endpoints
        return handleOfflineApiRequest(request);
    }
}

// Handle static file requests
async function handleStaticRequest(request) {
    // Try cache first for static files
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
        return cachedResponse;
    }
    
    try {
        // Fetch from network and cache
        const networkResponse = await fetch(request);
        const cache = await caches.open(STATIC_CACHE);
        cache.put(request, networkResponse.clone());
        return networkResponse;
    } catch (error) {
        console.log('Failed to fetch static file:', request.url);
        return new Response('File not available offline', { status: 404 });
    }
}

// Handle page requests
async function handlePageRequest(request) {
    try {
        // Try network first
        const networkResponse = await fetch(request);
        
        // Cache successful page responses
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.log('Network failed for page request, trying cache:', request.url);
        
        // Try to serve from cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Serve offline fallback page
        return handleOfflinePage(request);
    }
}

// Handle offline API requests
function handleOfflineApiRequest(request) {
    const url = new URL(request.url);
    
    // Return appropriate offline responses for different API endpoints
    if (url.pathname.includes('/api/files')) {
        return new Response(JSON.stringify({
            files: getOfflineFiles(),
            offline: true
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
    
    if (url.pathname.includes('/api/storage')) {
        return new Response(JSON.stringify({
            used: getOfflineStorageUsed(),
            total: 5 * 1024 * 1024 * 1024, // 5GB
            offline: true
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
    
    return new Response(JSON.stringify({
        error: 'This feature requires an internet connection',
        offline: true
    }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
    });
}

// Handle offline page requests
async function handleOfflinePage(request) {
    const url = new URL(request.url);
    
    // Try to serve a cached version of the dashboard for main pages
    if (OFFLINE_FALLBACK_PAGES.some(page => url.pathname.includes(page))) {
        const dashboardCache = await caches.match('/dashboard');
        if (dashboardCache) {
            return dashboardCache;
        }
    }
    
    // Serve offline fallback page
    return new Response(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Offline - SecureCloud</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        </head>
        <body class="bg-gray-100 dark:bg-gray-900">
            <div class="min-h-screen flex items-center justify-center">
                <div class="text-center p-8">
                    <i class="fas fa-wifi-slash text-6xl text-gray-400 mb-6"></i>
                    <h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-4">You're Offline</h1>
                    <p class="text-gray-600 dark:text-gray-300 mb-6">
                        Some features may not be available without an internet connection.
                    </p>
                    <button onclick="window.location.reload()" 
                            class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium">
                        <i class="fas fa-refresh mr-2"></i>Try Again
                    </button>
                </div>
            </div>
        </body>
        </html>
    `, {
        headers: { 'Content-Type': 'text/html' }
    });
}

// Background sync for offline actions
self.addEventListener('sync', event => {
    console.log('Background sync triggered:', event.tag);
    
    if (event.tag === 'upload-sync') {
        event.waitUntil(syncUploads());
    } else if (event.tag === 'delete-sync') {
        event.waitUntil(syncDeletes());
    } else if (event.tag === 'share-sync') {
        event.waitUntil(syncShares());
    }
});

// Sync offline uploads
async function syncUploads() {
    try {
        const offlineQueue = await getOfflineQueue();
        const uploadTasks = offlineQueue.filter(task => task.type === 'upload');
        
        for (const task of uploadTasks) {
            try {
                await retryUpload(task.data);
                await removeFromOfflineQueue(task.id);
                console.log('Successfully synced upload:', task.data.filename);
            } catch (error) {
                console.error('Failed to sync upload:', error);
            }
        }
    } catch (error) {
        console.error('Background sync failed:', error);
    }
}

// Sync offline deletes
async function syncDeletes() {
    try {
        const offlineQueue = await getOfflineQueue();
        const deleteTasks = offlineQueue.filter(task => task.type === 'delete');
        
        for (const task of deleteTasks) {
            try {
                await retryDelete(task.data);
                await removeFromOfflineQueue(task.id);
                console.log('Successfully synced delete:', task.data.fileId);
            } catch (error) {
                console.error('Failed to sync delete:', error);
            }
        }
    } catch (error) {
        console.error('Background sync failed:', error);
    }
}

// Sync offline shares
async function syncShares() {
    try {
        const offlineQueue = await getOfflineQueue();
        const shareTasks = offlineQueue.filter(task => task.type === 'share');
        
        for (const task of shareTasks) {
            try {
                await retryShare(task.data);
                await removeFromOfflineQueue(task.id);
                console.log('Successfully synced share:', task.data.fileId);
            } catch (error) {
                console.error('Failed to sync share:', error);
            }
        }
    } catch (error) {
        console.error('Background sync failed:', error);
    }
}

// Utility functions for offline data management
async function getOfflineQueue() {
    return new Promise((resolve) => {
        const channel = new BroadcastChannel('offline-queue');
        channel.postMessage({ type: 'GET_QUEUE' });
        
        channel.onmessage = (event) => {
            if (event.data.type === 'QUEUE_DATA') {
                resolve(event.data.queue || []);
            }
        };
        
        // Fallback timeout
        setTimeout(() => resolve([]), 1000);
    });
}

async function removeFromOfflineQueue(taskId) {
    const channel = new BroadcastChannel('offline-queue');
    channel.postMessage({ type: 'REMOVE_TASK', taskId });
}

function getOfflineFiles() {
    // Return cached file list or empty array
    return [];
}

function getOfflineStorageUsed() {
    // Return cached storage info or 0
    return 0;
}

// Retry functions for offline operations
async function retryUpload(uploadData) {
    const formData = new FormData();
    formData.append('file', uploadData.file);
    formData.append('encrypted', uploadData.encrypted);
    
    const response = await fetch('/upload', {
        method: 'POST',
        body: formData
    });
    
    if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
    }
    
    return response.json();
}

async function retryDelete(deleteData) {
    const response = await fetch(`/delete/${deleteData.fileId}`, {
        method: 'POST'
    });
    
    if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
    }
    
    return response.json();
}

async function retryShare(shareData) {
    const response = await fetch(`/share/${shareData.fileId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(shareData.options)
    });
    
    if (!response.ok) {
        throw new Error(`Share failed: ${response.statusText}`);
    }
    
    return response.json();
}

// Push notification handling
self.addEventListener('push', event => {
    if (!event.data) return;
    
    const data = event.data.json();
    const options = {
        body: data.body,
        icon: '/static/icons/icon-192x192.png',
        badge: '/static/icons/badge-72x72.png',
        vibrate: [200, 100, 200],
        data: data.data,
        actions: data.actions || []
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// Notification click handling
self.addEventListener('notificationclick', event => {
    event.notification.close();
    
    const urlToOpen = event.notification.data?.url || '/dashboard';
    
    event.waitUntil(
        clients.matchAll({ type: 'window' })
            .then(clientList => {
                // Focus existing window if available
                for (const client of clientList) {
                    if (client.url.includes(urlToOpen) && 'focus' in client) {
                        return client.focus();
                    }
                }
                
                // Open new window
                if (clients.openWindow) {
                    return clients.openWindow(urlToOpen);
                }
            })
    );
});

// Message handling for communication with main thread
self.addEventListener('message', event => {
    const { type, data } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
            
        case 'CACHE_FILE':
            cacheFile(data.url, data.content);
            break;
            
        case 'CLEAR_CACHE':
            clearCache(data.cacheName);
            break;
            
        default:
            console.log('Unknown message type:', type);
    }
});

// Cache a file programmatically
async function cacheFile(url, content) {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const response = new Response(content);
        await cache.put(url, response);
        console.log('File cached:', url);
    } catch (error) {
        console.error('Failed to cache file:', error);
    }
}

// Clear specific cache
async function clearCache(cacheName) {
    try {
        const deleted = await caches.delete(cacheName || DYNAMIC_CACHE);
        console.log('Cache cleared:', cacheName, deleted);
    } catch (error) {
        console.error('Failed to clear cache:', error);
    }
}

console.log('SecureCloud Service Worker loaded successfully');
