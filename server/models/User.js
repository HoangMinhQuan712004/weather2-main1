const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      index: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    cccd: {
      type: String,
      unique: true,
      sparse: true,
      trim: true,
    },
    dateOfBirth: {
      type: Date,
      required: function () {
        return this.cccd !== undefined;
      },
    },
    gender: {
      type: String,
      enum: ["Nam", "Nữ", "Khác", null],
      default: null,
    },
    address: {
      type: String,
      trim: true,
    },
    // Additional user information
    fullName: {
      type: String,
      trim: true,
    },
    phoneNumber: {
      type: String,
      trim: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: String,
    verificationExpires: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    // Existing fields
    favoriteCities: [
      {
        name: {
          type: String,
          required: true,
        },
        country: {
          type: String,
          required: true,
        },
        lat: {
          type: Number,
          required: true,
        },
        lon: {
          type: Number,
          required: true,
        },
        addedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    searchHistory: [
      {
        city: {
          type: String,
          required: true,
        },
        country: {
          type: String,
          required: true,
        },
        searchedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    preferences: {
      temperatureUnit: {
        type: String,
        enum: ["celsius", "fahrenheit"],
        default: "celsius",
      },
      language: {
        type: String,
        default: "en",
      },
    },
    lastLocation: {
      lat: Number,
      lon: Number,
      city: String,
      country: String,
      updatedAt: {
        type: Date,
        default: Date.now,
      },
    },
    cccd: {
      type: String,
      unique: true,
      sparse: true,
      trim: true,
    },
    discord: {
      userId: String,
      channelId: String,
      subscribed: {
        type: Boolean,
        default: false,
      },
      notificationCity: String,
      lastNotification: Date,
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Remove sensitive information from JSON output
userSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.password;
  delete user.verificationToken;
  delete user.verificationExpires;
  delete user.passwordResetToken;
  delete user.passwordResetExpires;
  return user;
};

// Indexes for better performance
userSchema.index({ "favoriteCities.name": 1, "favoriteCities.country": 1 });
userSchema.index({ "searchHistory.searchedAt": -1 });
userSchema.index({ cccd: 1 }); // Add index for CCCD field
userSchema.index({ email: 1 }); // Ensure email is indexed
userSchema.index({ username: 1 }); // Ensure username is indexed

// Virtual for user's full name
userSchema.virtual("displayName").get(function () {
  return this.fullName || this.username;
});

// Method to get basic user info
userSchema.methods.getPublicProfile = function () {
  const user = this.toObject();
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    dateOfBirth: user.dateOfBirth,
    gender: user.gender,
    preferences: user.preferences,
    createdAt: user.createdAt,
  };
};

module.exports = mongoose.model("User", userSchema);
