const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { uploadFile, generateVideoThumbnail } = require('../config/cloudinary');

// Ensure upload directories exist
const ensureDirectories = () => {
  const dirs = ['uploads/videos', 'uploads/images'];
  dirs.forEach(dir => {
    const fullPath = path.join(__dirname, '..', dir);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
  });
};

// Initialize directories on module load
ensureDirectories();

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'video') {
      cb(null, 'uploads/videos/');
    } else {
      cb(null, 'uploads/images/');
    }
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  // Define allowed file types
  const allowedImageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  const allowedVideoTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/quicktime'];

  if (file.fieldname === 'video') {
    if (allowedVideoTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid video format. Only MP4, AVI, and MOV files are allowed.'), false);
    }
  } else {
    if (allowedImageTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid image format. Only JPEG, PNG, and WebP files are allowed.'), false);
    }
  }
};

// Configure multer
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 3 * 1024 * 1024, // 3MB max (videos are larger, images will be well under this)
    files: 10 // Maximum 10 files
  }
});

// Middleware for single video upload
const uploadVideo = upload.single('video');

// Middleware for multiple image uploads
const uploadImages = upload.array('images', 10);

// Middleware for mixed upload (video + images)
const uploadMedia = upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'images', maxCount: 10 }
]);

// Process uploaded files and upload to Cloudinary
const processUploads = async (req, res, next) => {
  try {
    if (!req.files) {
      return next();
    }

    const uploadPromises = [];

    // Process video if uploaded
    if (req.files.video) {
      const videoFile = req.files.video[0];

      // Validate video duration (basic check)
      if (videoFile.size === 0) {
        return res.status(400).json({
          success: false,
          error: 'Video file is empty'
        });
      }

      try {
        // Upload to Cloudinary
        const result = await uploadFile(videoFile.path, {
          resource_type: 'video',
          quality: 'auto:good',
          format: 'mp4',
          transformation: [
            { width: 1280, height: 720, crop: 'limit' }
          ]
        });

        // Generate thumbnail
        const thumbnailUrl = await generateVideoThumbnail(result.url);

        uploadPromises.push(Promise.resolve({
          type: 'video',
          url: result.url,
          thumbnail: thumbnailUrl,
          duration: result.duration,
          size: result.bytes,
          quality: result.quality || 'medium'
        }));
      } catch (error) {
        console.error('Video upload error:', error);
        throw new Error('Failed to upload video. Please try again.');
      }
    }

    // Process images if uploaded
    if (req.files.images) {
      const imagePromises = req.files.images.map(async (imageFile, index) => {
        const result = await uploadFile(imageFile.path, {
          resource_type: 'image',
          quality: 'auto:good',
          format: 'auto',
          transformation: [
            { width: 800, height: 600, crop: 'limit' }
          ]
        });

        return {
          url: result.url,
          alt: `Image ${index + 1}`,
          order: index
        };
      });

      uploadPromises.push(...imagePromises);
    }

    // Wait for all uploads to complete
    const results = await Promise.all(uploadPromises);

    // Organize results
    if (req.files.video && req.files.images) {
      // Both video and images
      const videoResult = results.find(r => r.type === 'video');
      const imageResults = results.filter(r => !r.type);

      req.uploadedMedia = {
        video: videoResult,
        images: imageResults
      };
    } else if (req.files.video) {
      // Only video
      req.uploadedMedia = {
        video: results[0],
        images: []
      };
    } else if (req.files.images) {
      // Only images
      req.uploadedMedia = {
        video: null,
        images: results
      };
    }

    next();
  } catch (error) {
    console.error('Upload processing error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process uploads',
      details: error.message
    });
  }
};

// Error handling for multer
const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large',
        maxSize: req.files?.video ? '3MB for videos, 1MB for images' : '1MB for images'
      });
    }

    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        error: 'Too many files uploaded',
        maxFiles: 10
      });
    }

    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        error: 'Unexpected file field'
      });
    }
  }

  if (error.message.includes('Invalid') || error.message.includes('only')) {
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }

  next(error);
};

module.exports = {
  upload,
  uploadVideo,
  uploadImages,
  uploadMedia,
  processUploads,
  handleUploadError
};