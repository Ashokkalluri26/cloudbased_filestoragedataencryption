/**
 * WebAuthn (Passkeys) implementation for passwordless authentication
 */

class WebAuthnManager {
    constructor() {
        this.isSupported = this.checkSupport();
    }

    checkSupport() {
        return !!(navigator.credentials && navigator.credentials.create && navigator.credentials.get);
    }

    /**
     * Register a new passkey
     */
    async registerPasskey(deviceName = 'Unknown Device') {
        if (!this.isSupported) {
            throw new Error('WebAuthn is not supported in this browser');
        }

        try {
            // Get registration options from server
            const response = await fetch('/webauthn/register/begin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ device_name: deviceName })
            });

            if (!response.ok) {
                throw new Error('Failed to get registration options');
            }

            const options = await response.json();

            // Convert base64 strings to ArrayBuffers
            options.user.id = this.base64ToArrayBuffer(options.user.id);
            options.challenge = this.base64ToArrayBuffer(options.challenge);

            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map(cred => ({
                    ...cred,
                    id: this.base64ToArrayBuffer(cred.id)
                }));
            }

            // Create credential
            const credential = await navigator.credentials.create({
                publicKey: options
            });

            // Send credential to server
            const registrationResponse = await fetch('/webauthn/register/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    id: credential.id,
                    rawId: this.arrayBufferToBase64(credential.rawId),
                    response: {
                        attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
                        clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON),
                    },
                    type: credential.type,
                    device_name: deviceName
                })
            });

            if (!registrationResponse.ok) {
                throw new Error('Failed to complete registration');
            }

            const result = await registrationResponse.json();
            return result;

        } catch (error) {
            console.error('WebAuthn registration failed:', error);
            throw error;
        }
    }

    /**
     * Authenticate with passkey
     */
    async authenticateWithPasskey(email) {
        if (!this.isSupported) {
            throw new Error('WebAuthn is not supported in this browser');
        }

        try {
            // Get authentication options from server
            const response = await fetch('/webauthn/login/begin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: email })
            });

            if (!response.ok) {
                throw new Error('Failed to get authentication options');
            }

            const options = await response.json();

            // Convert base64 strings to ArrayBuffers
            options.challenge = this.base64ToArrayBuffer(options.challenge);
            
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: this.base64ToArrayBuffer(cred.id)
                }));
            }

            // Get credential
            const credential = await navigator.credentials.get({
                publicKey: options
            });

            // Send authentication response to server
            const authResponse = await fetch('/webauthn/login/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    id: credential.id,
                    rawId: this.arrayBufferToBase64(credential.rawId),
                    response: {
                        authenticatorData: this.arrayBufferToBase64(credential.response.authenticatorData),
                        clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON),
                        signature: this.arrayBufferToBase64(credential.response.signature),
                        userHandle: credential.response.userHandle ? this.arrayBufferToBase64(credential.response.userHandle) : null
                    },
                    type: credential.type
                })
            });

            if (!authResponse.ok) {
                throw new Error('Authentication failed');
            }

            const result = await authResponse.json();
            return result;

        } catch (error) {
            console.error('WebAuthn authentication failed:', error);
            throw error;
        }
    }

    /**
     * Check if user has registered passkeys
     */
    async hasPasskeys(email) {
        try {
            const response = await fetch('/api/user/passkeys', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: email })
            });

            if (response.ok) {
                const data = await response.json();
                return data.has_passkeys || false;
            }
            return false;
        } catch (error) {
            console.error('Failed to check passkeys:', error);
            return false;
        }
    }

    /**
     * Show biometric prompt for supported devices
     */
    async showBiometricPrompt() {
        if ('PublicKeyCredential' in window && 'isUserVerifyingPlatformAuthenticatorAvailable' in PublicKeyCredential) {
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            return available;
        }
        return false;
    }

    /**
     * Get available authenticator types
     */
    async getAuthenticatorInfo() {
        const info = {
            platform: false,
            crossPlatform: false,
            biometric: false
        };

        if ('PublicKeyCredential' in window) {
            if ('isUserVerifyingPlatformAuthenticatorAvailable' in PublicKeyCredential) {
                info.platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
                info.biometric = info.platform; // Platform authenticators typically support biometrics
            }

            if ('isConditionalMediationAvailable' in PublicKeyCredential) {
                info.conditional = await PublicKeyCredential.isConditionalMediationAvailable();
            }
        }

        return info;
    }

    // Utility methods
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// Global instance
window.webAuthnManager = new WebAuthnManager();
