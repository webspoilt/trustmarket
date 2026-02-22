const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/trustmarket';
    
    console.log('🔌 Connecting to MongoDB...');
    
    const conn = await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4, // Use IPv4, skip trying IPv6
      retryWrites: true,
      w: 'majority'
    });

    console.log(`📊 MongoDB Connected: ${conn.connection.host}`);
    console.log(`📊 Database Name: ${conn.connection.name}`);

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
      console.log('💡 If using MongoDB Atlas, check your connection string and network access');
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️ MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('🔄 MongoDB reconnected');
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('🔌 MongoDB connection closed through app termination');
        process.exit(0);
      } catch (error) {
        console.error('❌ Error closing MongoDB connection:', error);
        process.exit(1);
      }
    });

  } catch (error) {
    console.error('❌ Database connection failed:', error);
    console.log('\n💡 TROUBLESHOOTING TIPS:');
    console.log('1. Check your MONGODB_URI in .env file');
    console.log('2. For MongoDB Atlas: Ensure your IP is whitelisted');
    console.log('3. For local MongoDB: Make sure MongoDB is running');
    console.log('4. Check network connectivity');
    console.log('5. Verify your MongoDB Atlas cluster is active\n');
    
    process.exit(1);
  }
};

module.exports = { connectDB };