const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    index: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    index: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  favoriteCities: [{
    name: {
      type: String,
      required: true
    },
    country: {
      type: String,
      required: true
    },
    lat: {
      type: Number,
      required: true
    },
    lon: {
      type: Number,
      required: true
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  searchHistory: [{
    city: {
      type: String,
      required: true
    },
    country: {
      type: String,
      required: true
    },
    searchedAt: {
      type: Date,
      default: Date.now
    }
  }],
  preferences: {
    temperatureUnit: {
      type: String,
      enum: ['celsius', 'fahrenheit'],
      default: 'celsius'
    },
    language: {
      type: String,
      default: 'en'
    }
  },
  lastLocation: {
    lat: Number,
    lon: Number,
    city: String,
    country: String,
    updatedAt: {
      type: Date,
      default: Date.now
    }
  },
  discord: {
    userId: String,
    channelId: String,
    subscribed: {
      type: Boolean,
      default: false
    },
    notificationCity: String,
    lastNotification: Date
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  return user;
};

// Add indexes for better performance (removed duplicate email and username indexes)
userSchema.index({ 'favoriteCities.name': 1, 'favoriteCities.country': 1 });
userSchema.index({ 'searchHistory.searchedAt': -1 });

module.exports = mongoose.model('User', userSchema);
