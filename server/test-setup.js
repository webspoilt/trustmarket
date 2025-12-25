// Quick test script to verify database and media storage setup
const mongoose = require('mongoose');
const { cloudinary, uploadFile } = require('./config/cloudinary');

async function testSetup() {
  console.log('🧪 Testing TrustMarket Setup...\n');

  // Test 1: Database Connection
  console.log('📊 Testing Database Connection...');
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/trustmarket');
    console.log('✅ Database: Connected successfully');
    console.log(`📊 Host: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}\n`);
  } catch (error) {
    console.log('❌ Database: Connection failed');
    console.log('💡 Solution: Check your MONGODB_URI in .env file');
    console.log('💡 For MongoDB Atlas: Ensure IP whitelist and cluster is active\n');
  }

  // Test 2: Cloudinary Configuration
  console.log('📸 Testing Media Storage...');
  const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                         process.env.CLOUDINARY_CLOUD_NAME && 
                         process.env.CLOUDINARY_API_KEY !== 'demo';

  if (isRealCloudinary) {
    console.log('✅ Media Storage: Using Cloudinary');
    try {
      // Test Cloudinary configuration
      await cloudinary.api.ping();
      console.log('✅ Cloudinary: API connection successful\n');
    } catch (error) {
      console.log('❌ Cloudinary: API connection failed');
      console.log('💡 Solution: Check your Cloudinary credentials in .env file\n');
    }
  } else {
    console.log('✅ Media Storage: Using local file storage (demo mode)');
    console.log('💡 To use Cloudinary: Set real credentials in .env file\n');
  }

  // Test 3: Environment Variables
  console.log('🔧 Environment Variables Check:');
  const requiredVars = [
    'MONGODB_URI',
    'JWT_SECRET',
    'CLOUDINARY_CLOUD_NAME',
    'FRONTEND_URL'
  ];

  requiredVars.forEach(varName => {
    const value = process.env[varName];
    if (value && value !== 'demo') {
      console.log(`✅ ${varName}: Set`);
    } else if (varName === 'CLOUDINARY_CLOUD_NAME' && value === 'demo') {
      console.log(`⚠️ ${varName}: Demo mode (consider setting real Cloudinary credentials)`);
    } else {
      console.log(`❌ ${varName}: Not set or using demo value`);
    }
  });

  console.log('\n🎉 Setup Test Complete!');
  console.log('\n📋 Next Steps:');
  console.log('1. Fix any ❌ items above');
  console.log('2. For production: Set up MongoDB Atlas and Cloudinary');
  console.log('3. Run: npm start');
  console.log('4. Test: http://localhost:5000/api/health');
}

// Run the test
testSetup().catch(console.error);

// Export for use in other files
module.exports = { testSetup };