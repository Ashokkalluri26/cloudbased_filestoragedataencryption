/**
 * Client-side zero-knowledge encryption utilities
 * Uses Web Crypto API for AES-256-GCM encryption
 */

class CryptoManager {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.ivLength = 12; // 96 bits for GCM
    }

    /**
     * Generate a new encryption key
     */
    async generateKey() {
        return await window.crypto.subtle.generateKey(
            {
                name: this.algorithm,
                length: this.keyLength,
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Export key to raw format
     */
    async exportKey(key) {
        const exported = await window.crypto.subtle.exportKey('raw', key);
        return new Uint8Array(exported);
    }

    /**
     * Import key from raw format
     */
    async importKey(keyData) {
        return await window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: this.algorithm },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt file data
     */
    async encryptFile(fileData, key) {
        const iv = window.crypto.getRandomValues(new Uint8Array(this.ivLength));
        
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            fileData
        );

        // Combine IV and encrypted data
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);

        return {
            data: result,
            iv: iv,
            size: result.length
        };
    }

    /**
     * Decrypt file data
     */
    async decryptFile(encryptedData, key) {
        // Extract IV and encrypted content
        const iv = encryptedData.slice(0, this.ivLength);
        const data = encryptedData.slice(this.ivLength);

        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            data
        );

        return new Uint8Array(decrypted);
    }

    /**
     * Generate file hash for integrity verification
     */
    async generateHash(data) {
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Derive key from password using PBKDF2
     */
    async deriveKeyFromPassword(password, salt) {
        const encoder = new TextEncoder();
        const passwordKey = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: this.algorithm, length: this.keyLength },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate secure random salt
     */
    generateSalt() {
        return window.crypto.getRandomValues(new Uint8Array(16));
    }

    /**
     * Convert ArrayBuffer to Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    /**
     * Convert Base64 to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Encrypt file in chunks for large files
     */
    async encryptFileChunked(file, key, chunkSize = 1024 * 1024, progressCallback) {
        const chunks = [];
        const totalChunks = Math.ceil(file.size / chunkSize);
        
        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);
            
            const chunkData = await chunk.arrayBuffer();
            const encryptedChunk = await this.encryptFile(new Uint8Array(chunkData), key);
            
            chunks.push({
                index: i,
                data: encryptedChunk.data,
                size: encryptedChunk.size,
                hash: await this.generateHash(new Uint8Array(chunkData))
            });

            if (progressCallback) {
                progressCallback((i + 1) / totalChunks * 100);
            }
        }

        return chunks;
    }

    /**
     * Decrypt and reassemble chunked file
     */
    async decryptFileChunked(chunks, key, progressCallback) {
        const decryptedChunks = [];
        
        for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];
            const decryptedData = await this.decryptFile(chunk.data, key);
            decryptedChunks.push(decryptedData);

            if (progressCallback) {
                progressCallback((i + 1) / chunks.length * 100);
            }
        }

        // Combine all chunks
        const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const result = new Uint8Array(totalSize);
        let offset = 0;

        for (const chunk of decryptedChunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }

        return result;
    }
}

/**
 * Secure key storage using IndexedDB
 */
class SecureKeyStorage {
    constructor() {
        this.dbName = 'SecureCloudStorage';
        this.version = 1;
        this.storeName = 'keys';
    }

    async initDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName, { keyPath: 'id' });
                }
            };
        });
    }

    async storeKey(keyId, keyData, metadata = {}) {
        const db = await this.initDB();
        const transaction = db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        
        const keyRecord = {
            id: keyId,
            key: keyData,
            metadata: metadata,
            created: new Date().toISOString()
        };

        return new Promise((resolve, reject) => {
            const request = store.put(keyRecord);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async getKey(keyId) {
        const db = await this.initDB();
        const transaction = db.transaction([this.storeName], 'readonly');
        const store = transaction.objectStore(this.storeName);

        return new Promise((resolve, reject) => {
            const request = store.get(keyId);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async deleteKey(keyId) {
        const db = await this.initDB();
        const transaction = db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);

        return new Promise((resolve, reject) => {
            const request = store.delete(keyId);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async listKeys() {
        const db = await this.initDB();
        const transaction = db.transaction([this.storeName], 'readonly');
        const store = transaction.objectStore(this.storeName);

        return new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }
}

// Global instances
window.cryptoManager = new CryptoManager();
window.keyStorage = new SecureKeyStorage();
