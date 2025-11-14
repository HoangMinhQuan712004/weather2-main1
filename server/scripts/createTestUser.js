const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config();

const createTestUser = async () => {
  try {
    // Connect to MongoDB
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/weather-app';
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB');

    // Check if test user already exists
    const existingUser = await User.findOne({ email: 'leduc250824@gmail.com' });
    
    if (existingUser) {
      console.log('Test user already exists:', existingUser.email);
      console.log('Username:', existingUser.username);
      return;
    }

    // Create test user
    const testUser = new User({
      username: 'testuser',
      email: 'leduc250824@gmail.com',
      password: '123456' // This will be hashed automatically
    });

    await testUser.save();
    console.log('Test user created successfully!');
    console.log('Email:', testUser.email);
    console.log('Username:', testUser.username);
    console.log('Password: 123456');

  } catch (error) {
    console.error('Error creating test user:', error);
  } finally {
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB');
  }
};

// Run the script
createTestUser();
