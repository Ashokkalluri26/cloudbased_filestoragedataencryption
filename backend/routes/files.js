const express = require('express');
const multer = require('multer');
const { body, validationResult } = require('express-validator');
const File = require('../models/File');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');
const encryptionService = require('../utils/encryption');
const s3Service = require('../utils/s3Service');

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow common file types
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'image/jpeg',
      'image/png',
      'image/gif',
      'video/mp4',
      'text/plain',
      'application/zip'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not supported'), false);
    }
  }
});

// Upload file
router.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const { buffer, originalname, mimetype, size } = req.file;
    const { description, tags } = req.body;

    // Check user storage limit
    const user = await User.findById(req.user._id);
    if (user.storageUsed + size > user.storageLimit) {
      return res.status(400).json({ error: 'Storage limit exceeded' });
    }

    // Encrypt file
    const { encryptedData, iv, checksum } = encryptionService.encrypt(buffer);
    
    // Generate S3 key
    const s3Key = s3Service.generateS3Key(req.user._id, originalname);
    
    // Upload to S3
    await s3Service.uploadFile(encryptedData, s3Key, 'application/octet-stream');

    // Save file metadata
    const file = new File({
      fileName: originalname,
      originalName: originalname,
      mimeType: mimetype,
      size: size,
      encryptedSize: encryptedData.length,
      owner: req.user._id,
      s3Key: s3Key,
      encryptionIV: iv,
      checksum: checksum,
      description: description || '',
      tags: tags ? tags.split(',').map(tag => tag.trim()) : []
    });

    await file.save();

    // Update user storage
    user.storageUsed += size;
    await user.save();

    res.status(201).json({
      message: 'File uploaded successfully',
      file: {
        id: file._id,
        fileName: file.fileName,
        size: file.size,
        mimeType: file.mimeType,
        uploadedAt: file.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user files
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, search, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
    
    const query = { owner: req.user._id };
    
    if (search) {
      query.$or = [
        { fileName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const files = await File.find(query)
      .sort(sort)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-encryptionIV -checksum -s3Key');

    const total = await File.countDocuments(query);

    res.json({
      files,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Download file
router.get('/:fileId/download', authenticateToken, async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Download from S3
    const encryptedData = await s3Service.downloadFile(file.s3Key);
    
    // Decrypt file
    const decryptedData = encryptionService.decrypt(encryptedData, file.encryptionIV);
    
    // Verify checksum
    if (!encryptionService.verifyChecksum(decryptedData, file.checksum)) {
      throw new Error('File integrity check failed');
    }

    // Update download count
    await file.incrementDownload();

    res.set({
      'Content-Type': file.mimeType,
      'Content-Disposition': `attachment; filename="${file.fileName}"`,
      'Content-Length': decryptedData.length
    });

    res.send(decryptedData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete file
router.delete('/:fileId', authenticateToken, async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Delete from S3
    await s3Service.deleteFile(file.s3Key);

    // Update user storage
    const user = await User.findById(req.user._id);
    user.storageUsed -= file.size;
    await user.save();

    // Delete file record
    await File.findByIdAndDelete(file._id);

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Rename file
router.patch('/:fileId/rename', authenticateToken, [
  body('fileName').trim().isLength({ min: 1 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    file.fileName = req.body.fileName;
    await file.save();

    res.json({ message: 'File renamed successfully', file });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Share file
router.post('/:fileId/share', authenticateToken, async (req, res) => {
  try {
    const { expiresIn = 24 } = req.body; // hours
    
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    const shareToken = encryptionService.generateSecureToken();
    const expiresAt = new Date(Date.now() + expiresIn * 60 * 60 * 1000);

    file.isShared = true;
    file.shareToken = shareToken;
    file.shareExpiresAt = expiresAt;
    await file.save();

    const shareUrl = `${req.protocol}://${req.get('host')}/api/files/shared/${shareToken}`;

    res.json({
      message: 'File shared successfully',
      shareUrl,
      expiresAt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Download shared file
router.get('/shared/:shareToken', async (req, res) => {
  try {
    const file = await File.findOne({
      shareToken: req.params.shareToken,
      isShared: true,
      shareExpiresAt: { $gt: new Date() }
    });

    if (!file) {
      return res.status(404).json({ error: 'Shared file not found or expired' });
    }

    // Download from S3
    const encryptedData = await s3Service.downloadFile(file.s3Key);
    
    // Decrypt file
    const decryptedData = encryptionService.decrypt(encryptedData, file.encryptionIV);
    
    // Verify checksum
    if (!encryptionService.verifyChecksum(decryptedData, file.checksum)) {
      throw new Error('File integrity check failed');
    }

    // Update download count
    await file.incrementDownload();

    res.set({
      'Content-Type': file.mimeType,
      'Content-Disposition': `attachment; filename="${file.fileName}"`,
      'Content-Length': decryptedData.length
    });

    res.send(decryptedData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
