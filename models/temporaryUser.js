const mongoose = require('mongoose');

const TemporaryUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },

  password: {
    type: String,
    required: true
  },

  createdAt: {
    type: Date,
    default: Date.now,
    expires: 3600 // Automatically deletes the user after 1 hour (optional)
  }
});

module.exports = mongoose.model('TemporaryUser', TemporaryUserSchema);
