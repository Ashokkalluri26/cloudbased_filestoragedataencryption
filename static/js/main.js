/**
 * SecureCloud - Main Application JavaScript
 * Features: Real-time updates, offline support, accessibility, PWA functionality
 */

class SecureCloudApp {
    constructor() {
        this.socket = null;
        this.isOnline = navigator.onLine;
        this.offlineQueue = [];
        this.currentTheme = localStorage.getItem('theme') || 'light';
        this.highContrastMode = localStorage.getItem('highContrast') === 'true';
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeTheme();
        this.initializeAccessibility();
        this.initializeWebSocket();
        this.initializeOfflineSupport();
        this.initializePWA();
        this.initializeFileUpload();
        this.initializeSearch();
        this.initializeViewToggle();
    }

    setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            this.initializeComponents();
        });

        // Online/offline status
        window.addEventListener('online', () => {
            this.isOnline = true;
            this.updateConnectionStatus();
            this.processOfflineQueue();
        });

        window.addEventListener('offline', () => {
            this.isOnline = false;
            this.updateConnectionStatus();
        });

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            this.handleKeyboardNavigation(e);
        });

        // Theme toggle
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }

        // High contrast toggle
        const contrastToggle = document.getElementById('high-contrast-toggle');
        if (contrastToggle) {
            contrastToggle.addEventListener('click', () => this.toggleHighContrast());
        }

        // Mobile menu toggle
        const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
        const mobileMenu = document.getElementById('mobile-menu');
        if (mobileMenuToggle && mobileMenu) {
            mobileMenuToggle.addEventListener('click', () => {
                const isHidden = mobileMenu.classList.contains('hidden');
                mobileMenu.classList.toggle('hidden', !isHidden);
                mobileMenuToggle.setAttribute('aria-expanded', isHidden);
            });
        }
    }

    initializeComponents() {
        // Initialize upload functionality
        this.setupUploadHandlers();
        
        // Initialize file management
        this.setupFileHandlers();
        
        // Initialize real-time updates
        this.startRealTimeUpdates();
    }

    initializeTheme() {
        document.documentElement.classList.toggle('dark', this.currentTheme === 'dark');
        document.body.setAttribute('data-theme', this.currentTheme);
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        localStorage.setItem('theme', this.currentTheme);
        this.initializeTheme();
        
        // Announce theme change for screen readers
        this.announceToScreenReader(`Switched to ${this.currentTheme} mode`);
    }

    initializeAccessibility() {
        // Set up high contrast mode
        document.body.setAttribute('data-theme', this.highContrastMode ? 'high-contrast' : this.currentTheme);
        
        // Add focus indicators for keyboard navigation
        this.setupFocusManagement();
        
        // Set up ARIA live regions
        this.setupLiveRegions();
    }

    toggleHighContrast() {
        this.highContrastMode = !this.highContrastMode;
        localStorage.setItem('highContrast', this.highContrastMode);
        document.body.setAttribute('data-theme', this.highContrastMode ? 'high-contrast' : this.currentTheme);
        
        this.announceToScreenReader(`High contrast mode ${this.highContrastMode ? 'enabled' : 'disabled'}`);
    }

    setupFocusManagement() {
        // Add visible focus indicators
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                document.body.classList.add('keyboard-navigation');
            }
        });

        document.addEventListener('mousedown', () => {
            document.body.classList.remove('keyboard-navigation');
        });
    }

    setupLiveRegions() {
        // Create ARIA live region for announcements
        if (!document.getElementById('aria-live-region')) {
            const liveRegion = document.createElement('div');
            liveRegion.id = 'aria-live-region';
            liveRegion.setAttribute('aria-live', 'polite');
            liveRegion.setAttribute('aria-atomic', 'true');
            liveRegion.className = 'sr-only';
            document.body.appendChild(liveRegion);
        }
    }

    announceToScreenReader(message) {
        const liveRegion = document.getElementById('aria-live-region');
        if (liveRegion) {
            liveRegion.textContent = message;
            setTimeout(() => {
                liveRegion.textContent = '';
            }, 1000);
        }
    }

    handleKeyboardNavigation(e) {
        // Escape key handling
        if (e.key === 'Escape') {
            this.closeModals();
            this.clearSearch();
        }

        // Ctrl+K for search
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('file-search');
            if (searchInput) {
                searchInput.focus();
            }
        }

        // Ctrl+U for upload
        if (e.ctrlKey && e.key === 'u') {
            e.preventDefault();
            const uploadBtn = document.getElementById('upload-btn');
            if (uploadBtn) {
                uploadBtn.click();
            }
        }
    }

    initializeWebSocket() {
        if (typeof io !== 'undefined') {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('Connected to server');
                this.updateConnectionStatus();
            });
            
            this.socket.on('disconnect', () => {
                console.log('Disconnected from server');
                this.updateConnectionStatus();
            });
            
            this.socket.on('upload_progress', (data) => {
                this.updateUploadProgress(data);
            });
            
            this.socket.on('upload_complete', (data) => {
                this.handleUploadComplete(data);
            });
            
            this.socket.on('upload_error', (data) => {
                this.handleUploadError(data);
            });
            
            this.socket.on('activity_update', (data) => {
                this.updateActivityFeed(data);
            });
        }
    }

    initializeOfflineSupport() {
        // Register service worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then(registration => {
                    console.log('ServiceWorker registered:', registration);
                })
                .catch(error => {
                    console.log('ServiceWorker registration failed:', error);
                });
        }

        // Setup offline queue processing
        this.setupOfflineQueue();
    }

    setupOfflineQueue() {
        // Load offline queue from localStorage
        const savedQueue = localStorage.getItem('offlineQueue');
        if (savedQueue) {
            this.offlineQueue = JSON.parse(savedQueue);
        }
    }

    addToOfflineQueue(operation) {
        this.offlineQueue.push({
            ...operation,
            timestamp: Date.now()
        });
        localStorage.setItem('offlineQueue', JSON.stringify(this.offlineQueue));
    }

    processOfflineQueue() {
        if (this.offlineQueue.length === 0) return;

        this.announceToScreenReader('Processing offline actions');
        
        this.offlineQueue.forEach(async (operation, index) => {
            try {
                await this.processOfflineOperation(operation);
                this.offlineQueue.splice(index, 1);
            } catch (error) {
                console.error('Failed to process offline operation:', error);
            }
        });

        localStorage.setItem('offlineQueue', JSON.stringify(this.offlineQueue));
    }

    async processOfflineOperation(operation) {
        switch (operation.type) {
            case 'upload':
                return await this.retryUpload(operation.data);
            case 'delete':
                return await this.retryDelete(operation.data);
            case 'share':
                return await this.retryShare(operation.data);
            default:
                throw new Error(`Unknown operation type: ${operation.type}`);
        }
    }

    initializePWA() {
        // Handle install prompt
        let deferredPrompt;
        
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            this.showInstallButton();
        });

        // Handle app installation
        const installBtn = document.getElementById('install-btn');
        if (installBtn) {
            installBtn.addEventListener('click', async () => {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    const { outcome } = await deferredPrompt.userChoice;
                    console.log(`User response to install prompt: ${outcome}`);
                    deferredPrompt = null;
                    this.hideInstallButton();
                }
            });
        }
    }

    showInstallButton() {
        const installBtn = document.getElementById('install-btn');
        if (installBtn) {
            installBtn.classList.remove('hidden');
        }
    }

    hideInstallButton() {
        const installBtn = document.getElementById('install-btn');
        if (installBtn) {
            installBtn.classList.add('hidden');
        }
    }

    initializeFileUpload() {
        const uploadBtn = document.getElementById('upload-btn');
        const uploadZone = document.getElementById('upload-zone');
        
        if (uploadBtn) {
            uploadBtn.addEventListener('click', () => this.openUploadModal());
        }

        if (uploadZone) {
            this.setupDragAndDrop(uploadZone);
        }
    }

    setupDragAndDrop(uploadZone) {
        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });

        uploadZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
        });

        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            
            const files = Array.from(e.dataTransfer.files);
            this.handleFileSelection(files);
        });
    }

    openUploadModal() {
        // Create upload modal dynamically
        const modal = this.createUploadModal();
        document.body.appendChild(modal);
        modal.classList.add('show');
        
        // Focus management
        const firstInput = modal.querySelector('input[type="file"]');
        if (firstInput) {
            firstInput.focus();
        }
    }

    createUploadModal() {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content" role="dialog" aria-labelledby="upload-modal-title" aria-modal="true">
                <div class="modal-header">
                    <h2 id="upload-modal-title" class="text-xl font-semibold text-gray-900 dark:text-white">
                        Upload Files
                    </h2>
                    <button type="button" class="text-gray-400 hover:text-gray-600" onclick="this.closest('.modal-overlay').remove()" aria-label="Close">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="upload-zone" id="modal-upload-zone">
                        <div class="text-center py-8">
                            <i class="fas fa-cloud-upload-alt text-4xl text-gray-400 mb-4"></i>
                            <p class="text-lg font-medium text-gray-900 dark:text-white mb-2">Drop files here or click to browse</p>
                            <p class="text-sm text-gray-500 dark:text-gray-400">Maximum file size: 100MB</p>
                            <input type="file" id="file-input" multiple class="hidden" accept="*/*">
                        </div>
                    </div>
                    <div id="upload-progress" class="hidden mt-4">
                        <div class="space-y-2" id="progress-list"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-secondary" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                    <button type="button" class="btn-primary" id="start-upload" disabled>Upload Files</button>
                </div>
            </div>
        `;

        // Setup modal event listeners
        this.setupModalEventListeners(modal);
        
        return modal;
    }

    setupModalEventListeners(modal) {
        const fileInput = modal.querySelector('#file-input');
        const uploadZone = modal.querySelector('#modal-upload-zone');
        const startUploadBtn = modal.querySelector('#start-upload');
        
        uploadZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => this.handleFileSelection(Array.from(e.target.files)));
        startUploadBtn.addEventListener('click', () => this.startUpload());
        
        this.setupDragAndDrop(uploadZone);
    }

    handleFileSelection(files) {
        this.selectedFiles = files;
        const startUploadBtn = document.querySelector('#start-upload');
        if (startUploadBtn) {
            startUploadBtn.disabled = files.length === 0;
            startUploadBtn.textContent = `Upload ${files.length} file${files.length !== 1 ? 's' : ''}`;
        }

        this.announceToScreenReader(`${files.length} file${files.length !== 1 ? 's' : ''} selected for upload`);
    }

    async startUpload() {
        if (!this.selectedFiles || this.selectedFiles.length === 0) return;

        const progressContainer = document.getElementById('upload-progress');
        const progressList = document.getElementById('progress-list');
        
        progressContainer.classList.remove('hidden');
        
        for (const file of this.selectedFiles) {
            await this.uploadFile(file, progressList);
        }
    }

    async uploadFile(file, progressContainer) {
        // Create progress item
        const progressItem = document.createElement('div');
        progressItem.className = 'flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg';
        progressItem.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="file-icon ${this.getFileCategory(file.name)}">
                    <i class="fas fa-file"></i>
                </div>
                <div>
                    <p class="text-sm font-medium text-gray-900 dark:text-white">${file.name}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400">${this.formatBytes(file.size)}</p>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <div class="progress-bar w-24">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <span class="text-xs text-gray-500 dark:text-gray-400">0%</span>
            </div>
        `;
        
        progressContainer.appendChild(progressItem);

        try {
            // Client-side encryption
            const encryptedFile = await this.encryptFile(file);
            
            // Upload with chunking for large files
            if (file.size > 5 * 1024 * 1024) { // 5MB threshold
                await this.uploadFileChunked(encryptedFile, progressItem);
            } else {
                await this.uploadFileStandard(encryptedFile, progressItem);
            }
            
        } catch (error) {
            this.handleUploadError({ error: error.message, filename: file.name });
        }
    }

    async encryptFile(file) {
        // Generate encryption key
        const key = await window.cryptoManager.generateKey();
        
        // Encrypt file data
        const fileData = await file.arrayBuffer();
        const encrypted = await window.cryptoManager.encryptFile(new Uint8Array(fileData), key);
        
        // Store key securely
        await window.keyStorage.storeKey(`file_${Date.now()}`, key);
        
        return {
            originalFile: file,
            encryptedData: encrypted.data,
            key: await window.cryptoManager.exportKey(key)
        };
    }

    updateConnectionStatus() {
        const syncStatus = document.getElementById('sync-status');
        const lastSync = document.getElementById('last-sync');
        
        if (syncStatus) {
            if (this.isOnline && this.socket?.connected) {
                syncStatus.innerHTML = '<i class="fas fa-check-circle mr-1"></i>Online';
                syncStatus.className = 'text-lg font-semibold text-green-600 dark:text-green-400';
            } else {
                syncStatus.innerHTML = '<i class="fas fa-exclamation-triangle mr-1"></i>Offline';
                syncStatus.className = 'text-lg font-semibold text-yellow-600 dark:text-yellow-400';
            }
        }
        
        if (lastSync) {
            lastSync.textContent = `Last sync: ${this.isOnline ? 'Just now' : 'Offline'}`;
        }
    }

    initializeSearch() {
        const searchInput = document.getElementById('file-search');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.performSearch(e.target.value);
                }, 300);
            });
        }
    }

    performSearch(query) {
        const fileItems = document.querySelectorAll('.file-item');
        let visibleCount = 0;
        
        fileItems.forEach(item => {
            const filename = item.dataset.filename?.toLowerCase() || '';
            const category = item.dataset.category?.toLowerCase() || '';
            const isVisible = !query || filename.includes(query.toLowerCase()) || category.includes(query.toLowerCase());
            
            item.style.display = isVisible ? '' : 'none';
            if (isVisible) visibleCount++;
        });
        
        this.announceToScreenReader(`${visibleCount} files found`);
    }

    initializeViewToggle() {
        const viewGrid = document.getElementById('view-grid');
        const viewList = document.getElementById('view-list');
        const filesList = document.getElementById('files-list');
        const filesGrid = document.getElementById('files-grid');
        
        if (viewGrid && viewList && filesList && filesGrid) {
            viewGrid.addEventListener('click', () => {
                filesList.classList.add('hidden');
                filesGrid.classList.remove('hidden');
                viewGrid.classList.add('text-primary-600');
                viewList.classList.remove('text-primary-600');
                this.announceToScreenReader('Switched to grid view');
            });
            
            viewList.addEventListener('click', () => {
                filesGrid.classList.add('hidden');
                filesList.classList.remove('hidden');
                viewList.classList.add('text-primary-600');
                viewGrid.classList.remove('text-primary-600');
                this.announceToScreenReader('Switched to list view');
            });
        }
    }

    getFileCategory(filename) {
        const ext = filename.split('.').pop()?.toLowerCase();
        const categoryMap = {
            'pdf': 'document',
            'doc': 'document', 'docx': 'document',
            'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image',
            'mp4': 'video', 'avi': 'video', 'mov': 'video',
            'mp3': 'audio', 'wav': 'audio',
            'zip': 'archive', 'rar': 'archive',
            'js': 'code', 'py': 'code', 'html': 'code'
        };
        return categoryMap[ext] || 'other';
    }

    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    closeModals() {
        document.querySelectorAll('.modal-overlay').forEach(modal => modal.remove());
    }

    clearSearch() {
        const searchInput = document.getElementById('file-search');
        if (searchInput && searchInput.value) {
            searchInput.value = '';
            this.performSearch('');
        }
    }
}

// Global functions for backward compatibility
window.downloadFile = function(fileId) {
    window.location.href = `/download/${fileId}`;
};

window.shareFile = function(fileId) {
    fetch(`/share/${fileId}`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.share_url) {
                navigator.clipboard.writeText(data.share_url).then(() => {
                    app.announceToScreenReader('Share link copied to clipboard');
                });
            }
        });
};

window.deleteFile = function(fileId) {
    if (confirm('Are you sure you want to delete this file?')) {
        fetch(`/delete/${fileId}`, { method: 'POST' })
            .then(response => {
                if (response.ok) {
                    location.reload();
                } else {
                    app.announceToScreenReader('Failed to delete file');
                }
            });
    }
};

// Initialize the application
const app = new SecureCloudApp();

function uploadFile() {
    const form = document.getElementById('uploadForm');
    const fileInput = document.getElementById('file');
    const progressBar = document.getElementById('uploadProgress');
    const uploadBtn = document.querySelector('#uploadModal .btn-primary');
    
    if (!fileInput.files[0]) {
        showNotification('Please select a file', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    // Show loading state
    uploadBtn.innerHTML = '<span class="loading"></span> Uploading...';
    uploadBtn.disabled = true;
    progressBar.classList.remove('d-none');
    
    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('File uploaded successfully!', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showNotification('Upload failed: ' + data.error, 'error');
        }
    })
    .catch(error => {
        showNotification('Upload failed: ' + error, 'error');
    })
    .finally(() => {
        uploadBtn.innerHTML = 'Upload';
        uploadBtn.disabled = false;
        progressBar.classList.add('d-none');
    });
}

function deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file?')) {
        return;
    }
    
    const deleteBtn = document.querySelector(`[onclick="deleteFile(${fileId})"]`);
    deleteBtn.innerHTML = '<span class="loading"></span>';
    deleteBtn.disabled = true;
    
    fetch(`/delete/${fileId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('File deleted successfully!', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showNotification('Delete failed: ' + data.error, 'error');
        }
    })
    .catch(error => {
        showNotification('Delete failed: ' + error, 'error');
    })
    .finally(() => {
        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
        deleteBtn.disabled = false;
    });
}

function shareFile(fileId) {
    const shareBtn = document.querySelector(`[onclick="shareFile(${fileId})"]`);
    shareBtn.innerHTML = '<span class="loading"></span>';
    shareBtn.disabled = true;
    
    fetch(`/share/${fileId}`)
    .then(response => response.json())
    .then(data => {
        if (data.share_url) {
            document.getElementById('shareLink').value = data.share_url;
            new bootstrap.Modal(document.getElementById('shareModal')).show();
            showNotification('Share link created!', 'success');
        } else {
            showNotification('Failed to create share link: ' + data.error, 'error');
        }
    })
    .catch(error => {
        showNotification('Failed to create share link: ' + error, 'error');
    })
    .finally(() => {
        shareBtn.innerHTML = '<i class="fas fa-share"></i>';
        shareBtn.disabled = false;
    });
}

function copyToClipboard() {
    const shareLink = document.getElementById('shareLink');
    shareLink.select();
    document.execCommand('copy');
    
    const button = event.target;
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i>';
    button.classList.add('btn-success');
    button.classList.remove('btn-outline-secondary');
    
    showNotification('Link copied to clipboard!', 'success');
    
    setTimeout(() => {
        button.innerHTML = originalText;
        button.classList.remove('btn-success');
        button.classList.add('btn-outline-secondary');
    }, 2000);
}

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show notification-toast`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        animation: slideInRight 0.5s ease-out;
    `;
    
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.5s ease-in';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 500);
        }
    }, 5000);
}

// Drag and drop functionality
document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('file');
    const uploadModal = document.getElementById('uploadModal');
    
    if (fileInput) {
        // Create drag and drop area
        const dragArea = document.createElement('div');
        dragArea.className = 'upload-area mt-3';
        dragArea.innerHTML = `
            <i class="fas fa-cloud-upload-alt fa-3x mb-3 text-muted"></i>
            <p class="mb-0">Drag and drop files here or click to browse</p>
        `;
        
        fileInput.parentNode.insertBefore(dragArea, fileInput.nextSibling);
        
        // Drag and drop events
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dragArea.addEventListener(eventName, preventDefaults, false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        ['dragenter', 'dragover'].forEach(eventName => {
            dragArea.addEventListener(eventName, () => dragArea.classList.add('dragover'), false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dragArea.addEventListener(eventName, () => dragArea.classList.remove('dragover'), false);
        });
        
        dragArea.addEventListener('drop', handleDrop, false);
        dragArea.addEventListener('click', () => fileInput.click());
        
        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            
            if (files.length > 0) {
                fileInput.files = files;
                dragArea.innerHTML = `
                    <i class="fas fa-file fa-2x mb-3 text-success"></i>
                    <p class="mb-0 text-success">File selected: ${files[0].name}</p>
                `;
            }
        }
        
        // File input change event
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                dragArea.innerHTML = `
                    <i class="fas fa-file fa-2x mb-3 text-success"></i>
                    <p class="mb-0 text-success">File selected: ${this.files[0].name}</p>
                `;
            }
        });
    }
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    .notification-toast {
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        backdrop-filter: blur(10px);
        border: none;
    }
`;
document.head.appendChild(style);
