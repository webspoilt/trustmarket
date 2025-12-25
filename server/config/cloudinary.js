const cloudinary = require('cloudinary').v2;
const fs = require('fs');
const path = require('path');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'demo',
  api_key: process.env.CLOUDINARY_API_KEY || 'demo',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'demo'
});

const uploadFile = async (filePath, options = {}) => {
  try {
    // Check if we're using real Cloudinary credentials
    const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                           process.env.CLOUDINARY_CLOUD_NAME && 
                           process.env.CLOUDINARY_API_KEY !== 'demo';

    if (isRealCloudinary) {
      // Use Cloudinary for real file upload
      const defaultOptions = {
        resource_type: 'auto',
        quality: 'auto:good',
        fetch_format: 'auto',
        folder: 'trustmarket',
        ...options
      };

      const result = await cloudinary.uploader.upload(filePath, defaultOptions);
      
      return {
        public_id: result.public_id,
        url: result.secure_url,
        width: result.width,
        height: result.height,
        format: result.format,
        resource_type: result.resource_type,
        duration: result.duration || null,
        bytes: result.bytes
      };
    } else {
      // Use local storage fallback for demo
      console.log('🖼️ Using local storage fallback (not Cloudinary)');
      
      const fileName = path.basename(filePath);
      const timestamp = Date.now();
      const newFileName = `${timestamp}-${fileName}`;
      const uploadsDir = path.join(__dirname, '../uploads');
      const newFilePath = path.join(uploadsDir, newFileName);
      
      // Create uploads directory if it doesn't exist
      if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
      }
      
      // Copy file to uploads directory
      fs.copyFileSync(filePath, newFilePath);
      
      // Get file stats
      const stats = fs.statSync(newFilePath);
      
      return {
        public_id: newFileName,
        url: `/uploads/${newFileName}`,
        width: null,
        height: null,
        format: path.extname(fileName).substring(1),
        resource_type: 'image',
        duration: null,
        bytes: stats.size
      };
    }
  } catch (error) {
    console.error('❌ Cloudinary upload error:', error);
    throw new Error('File upload failed');
  }
};

const deleteFile = async (publicId) => {
  try {
    // Check if we're using real Cloudinary credentials
    const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                           process.env.CLOUDINARY_CLOUD_NAME && 
                           process.env.CLOUDINARY_API_KEY !== 'demo';

    if (isRealCloudinary) {
      await cloudinary.uploader.destroy(publicId);
      return { success: true };
    } else {
      // Delete from local storage
      const uploadsDir = path.join(__dirname, '../uploads');
      const filePath = path.join(uploadsDir, publicId);
      
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return { success: true };
      }
      return { success: false, message: 'File not found' };
    }
  } catch (error) {
    console.error('❌ Cloudinary delete error:', error);
    throw new Error('File deletion failed');
  }
};

const generateVideoThumbnail = async (videoUrl) => {
  try {
    // Check if we're using real Cloudinary credentials
    const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                           process.env.CLOUDINARY_CLOUD_NAME && 
                           process.env.CLOUDINARY_API_KEY !== 'demo';

    if (isRealCloudinary && videoUrl.includes('cloudinary.com')) {
      const thumbnailUrl = cloudinary.url(videoUrl, {
        resource_type: 'video',
        start_offset: '0',
        format: 'jpg',
        transformation: [
          { width: 320, height: 240, crop: 'fill' },
          { quality: 'auto:good' }
        ]
      });
      
      return thumbnailUrl;
    } else {
      // Return a placeholder thumbnail for demo/local
      return '/api/placeholder/320/240';
    }
  } catch (error) {
    console.error('❌ Thumbnail generation error:', error);
    return '/api/placeholder/320/240';
  }
};

// Middleware to serve uploaded files
const serveUploadMiddleware = (req, res) => {
  const uploadsDir = path.join(__dirname, '../uploads');
  res.sendFile(path.join(uploadsDir, req.params.filename));
};

module.exports = {
  cloudinary,
  uploadFile,
  deleteFile,
  generateVideoThumbnail,
  serveUploadMiddleware
};