const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'demo',
  api_key: process.env.CLOUDINARY_API_KEY || 'demo',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'demo'
});

const uploadFile = async (filePath, options = {}) => {
  try {
    const defaultOptions = {
      resource_type: 'auto',
      quality: 'auto:good',
      fetch_format: 'auto',
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
  } catch (error) {
    console.error('❌ Cloudinary upload error:', error);
    throw new Error('File upload failed');
  }
};

const deleteFile = async (publicId) => {
  try {
    await cloudinary.uploader.destroy(publicId);
    return { success: true };
  } catch (error) {
    console.error('❌ Cloudinary delete error:', error);
    throw new Error('File deletion failed');
  }
};

const generateVideoThumbnail = async (videoUrl) => {
  try {
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
  } catch (error) {
    console.error('❌ Thumbnail generation error:', error);
    return null;
  }
};

module.exports = {
  cloudinary,
  uploadFile,
  deleteFile,
  generateVideoThumbnail
};