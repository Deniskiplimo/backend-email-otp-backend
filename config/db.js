require('dotenv').config(); // Load environment variables from .env file
const mongoose = require('mongoose');

const connectDB = async () => {
  if (mongoose.connection.readyState === 0) { // 0: disconnected
    try {
      await mongoose.connect(process.env.MONGODB_URI); // Removed deprecated options
      console.log('MongoDB Atlas connected successfully...');
    } catch (err) {
      console.error('Error connecting to MongoDB Atlas:', err);
      // Instead of exiting, we log the error and let the server continue running
    }
  } else {
    console.log('Already connected to MongoDB');
  }
};

module.exports = connectDB;
  