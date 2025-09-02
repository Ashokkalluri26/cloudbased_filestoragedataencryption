const encryptionService = require('../utils/encryption');
const crypto = require('crypto');

describe('Encryption Service', () => {
  const testData = Buffer.from('This is a test file content for encryption testing');
  
  beforeAll(() => {
    // Set test encryption key
    process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
  });

  test('should encrypt and decrypt data correctly', () => {
    const { encryptedData, iv, checksum } = encryptionService.encrypt(testData);
    
    expect(encryptedData).toBeInstanceOf(Buffer);
    expect(iv).toBeDefined();
    expect(checksum).toBeDefined();
    expect(encryptedData.length).toBeGreaterThan(testData.length);
    
    const decryptedData = encryptionService.decrypt(encryptedData, iv);
    expect(decryptedData).toEqual(testData);
  });

  test('should generate different encrypted data for same input', () => {
    const result1 = encryptionService.encrypt(testData);
    const result2 = encryptionService.encrypt(testData);
    
    expect(result1.encryptedData).not.toEqual(result2.encryptedData);
    expect(result1.iv).not.toEqual(result2.iv);
    expect(result1.checksum).toEqual(result2.checksum); // Same input = same checksum
  });

  test('should verify checksum correctly', () => {
    const { checksum } = encryptionService.encrypt(testData);
    
    expect(encryptionService.verifyChecksum(testData, checksum)).toBe(true);
    expect(encryptionService.verifyChecksum(Buffer.from('different data'), checksum)).toBe(false);
  });

  test('should generate secure tokens', () => {
    const token1 = encryptionService.generateSecureToken();
    const token2 = encryptionService.generateSecureToken();
    
    expect(token1).toBeDefined();
    expect(token2).toBeDefined();
    expect(token1).not.toEqual(token2);
    expect(token1.length).toBe(64); // 32 bytes = 64 hex chars
  });

  test('should fail decryption with wrong IV', () => {
    const { encryptedData } = encryptionService.encrypt(testData);
    const wrongIV = crypto.randomBytes(16).toString('hex');
    
    expect(() => {
      encryptionService.decrypt(encryptedData, wrongIV);
    }).toThrow();
  });

  test('should fail with corrupted encrypted data', () => {
    const { encryptedData, iv } = encryptionService.encrypt(testData);
    const corruptedData = Buffer.from(encryptedData);
    corruptedData[0] = corruptedData[0] ^ 0xFF; // Flip bits
    
    expect(() => {
      encryptionService.decrypt(corruptedData, iv);
    }).toThrow();
  });
});
