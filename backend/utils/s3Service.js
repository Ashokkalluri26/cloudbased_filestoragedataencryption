const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');

class S3Service {
  constructor() {
    this.s3 = new AWS.S3({
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      region: process.env.AWS_REGION || 'us-east-1'
    });
    this.bucketName = process.env.AWS_S3_BUCKET;
    
    if (!this.bucketName) {
      throw new Error('AWS_S3_BUCKET environment variable is required');
    }
  }

  generateS3Key(userId, originalFileName) {
    const timestamp = Date.now();
    const uuid = uuidv4();
    const extension = originalFileName.split('.').pop();
    return `users/${userId}/${timestamp}-${uuid}.${extension}`;
  }

  async uploadFile(buffer, s3Key, contentType) {
    try {
      const params = {
        Bucket: this.bucketName,
        Key: s3Key,
        Body: buffer,
        ContentType: contentType,
        ServerSideEncryption: 'AES256',
        Metadata: {
          'uploaded-at': new Date().toISOString()
        }
      };

      const result = await this.s3.upload(params).promise();
      return {
        location: result.Location,
        etag: result.ETag,
        key: result.Key
      };
    } catch (error) {
      throw new Error(`S3 upload failed: ${error.message}`);
    }
  }

  async downloadFile(s3Key) {
    try {
      const params = {
        Bucket: this.bucketName,
        Key: s3Key
      };

      const result = await this.s3.getObject(params).promise();
      return result.Body;
    } catch (error) {
      if (error.code === 'NoSuchKey') {
        throw new Error('File not found in storage');
      }
      throw new Error(`S3 download failed: ${error.message}`);
    }
  }

  async deleteFile(s3Key) {
    try {
      const params = {
        Bucket: this.bucketName,
        Key: s3Key
      };

      await this.s3.deleteObject(params).promise();
      return true;
    } catch (error) {
      throw new Error(`S3 delete failed: ${error.message}`);
    }
  }

  async getFileMetadata(s3Key) {
    try {
      const params = {
        Bucket: this.bucketName,
        Key: s3Key
      };

      const result = await this.s3.headObject(params).promise();
      return {
        size: result.ContentLength,
        lastModified: result.LastModified,
        etag: result.ETag,
        contentType: result.ContentType
      };
    } catch (error) {
      throw new Error(`Failed to get file metadata: ${error.message}`);
    }
  }

  async generatePresignedUrl(s3Key, expiresIn = 3600) {
    try {
      const params = {
        Bucket: this.bucketName,
        Key: s3Key,
        Expires: expiresIn
      };

      return this.s3.getSignedUrl('getObject', params);
    } catch (error) {
      throw new Error(`Failed to generate presigned URL: ${error.message}`);
    }
  }
}

module.exports = new S3Service();
