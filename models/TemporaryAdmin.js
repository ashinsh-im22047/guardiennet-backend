const mongoose = require('mongoose');

const temporaryAdminSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'admin' },
  createdAt: { type: Date, default: Date.now, expires: 900 }, // 15 mins expiry
});

module.exports = mongoose.model('TemporaryAdmin', temporaryAdminSchema);
