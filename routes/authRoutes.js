const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const protect = require('../middleware/authMiddleware');
const User = require('../models/user');
const TemporaryUser = require('../models/temporaryUser');
const TemporaryAdmin = require('../models/TemporaryAdmin'); 


// Nodemailer transporter (unchanged)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// REGISTER route
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Also check if email exists in TemporaryUser collection
    const tempUserExists = await TemporaryUser.findOne({ email });
    if (tempUserExists) {
      return res.status(400).json({ message: 'Verification already sent. Please check your email.' });
    }
    // Hash password once here
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save to TemporaryUser collection
    const tempUser = new TemporaryUser({
      username,
      email,
      password: hashedPassword,
    });

    await tempUser.save();

    // Create JWT token with only email (or username + email)
    const token = jwt.sign(
      { email, username },
      process.env.JWT_EMAIL_SECRET,
      { expiresIn: '15m' }
    );

    // Verification URL
    const verifyUrl = `${process.env.BACKEND_URL}/api/auth/verify/${token}`;

    const html = `
      <h2>Welcome to GuardianNet</h2>
      <p>Click below to verify your email and complete registration:</p>
      <a href="${verifyUrl}">${verifyUrl}</a>
      <p>This link expires in 15 minutes.</p>
    `;

    await transporter.sendMail({
      from: `"GuardianNet" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Verify your email',
      html,
    });

    res.status(200).json({ message: 'Verification email sent. Please check your inbox.' });
  } catch (err) {
    console.error('Register Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// VERIFY route
router.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_EMAIL_SECRET);
    const { email } = decoded;

    // Check if user already verified
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.redirect(`${process.env.FRONTEND_URL}/login?alreadyVerified=true`);
    }

    // Find TemporaryUser data
    const tempUser = await TemporaryUser.findOne({ email });
    if (!tempUser) {
      return res.status(400).send("Verification link expired or invalid");
    }

    // Create final user from TemporaryUser data
    const newUser = new User({
      username: tempUser.username,
      email: tempUser.email,
      password: tempUser.password, // hashed password
      isVerified: true,
    });

    await newUser.save();

    // Remove temp user record after successful verification
    await TemporaryUser.deleteOne({ email });

    // Redirect with success
    res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (err) {
    console.error("Verification Error:", err);
    res.status(400).send("❌ Invalid or expired link");
  }
});

// LOGIN route remains unchanged
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Email and password are required.' });

  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user)
      return res.status(400).json({ message: 'Invalid email or password' });

if (!user.isVerified) {
  return res.status(400).json({ message: 'Please verify your email before logging in.' });
}

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Login Error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// ========== FORGOT PASSWORD ==========
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: 'User with this email does not exist' });

    const resetToken = user.generatePasswordResetToken();
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    const mailOptions = {
      from: `"GuardianNet" <${process.env.GMAIL_USER}>`,
      to: user.email,
      subject: 'Reset Your Password',
      html: `
        <h3>Hello ${user.username},</h3>
        <p>Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link expires in 10 minutes.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Reset password email sent' });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ========== CHANGE PASSWORD ==========
router.post('/change-password', protect, async (req, res) => {
  const { oldPassword, newPassword, confirmNewPassword } = req.body;

  // 1. Basic validations
  if (!oldPassword || !newPassword || !confirmNewPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ message: 'New passwords do not match' });
  }

  if (newPassword === oldPassword) {
    return res.status(400).json({ message: 'New password must be different from old password' });
  }

  try {
    const user = await User.findById(req.user._id).select('+password');
    console.log("user details", user);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Old password is incorrect' });
    }

    // 2. Hash new password and save
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Change Password Error:', error.message);
    return res.status(500).json({ message: 'Something went wrong' });
  }
});

//renew password
router.post('/renew-password/:token', async (req, res) => {
  const { token } = req.params;

  const { newPassword, confirmNewPassword } = req.body;

  if (!newPassword || !confirmNewPassword) {
    return res.status(400).json({ message: 'Please fill all fields' });
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired password reset token' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset Password Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add required model
router.post('/register-admin', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if already in temporary admin collection
    const tempAdminExists = await TemporaryAdmin.findOne({ email });
    if (tempAdminExists) {
      return res.status(400).json({ message: 'Verification already sent. Please check your email.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Save to TemporaryAdmin collection
    const tempAdmin = new TemporaryAdmin({
      username,
      email,
      password: hashedPassword,
      role: 'admin', // ✅ Set role here
    });

    await tempAdmin.save();

    const token = jwt.sign(
      { email, username, role: 'admin' },
      process.env.JWT_EMAIL_SECRET,
      { expiresIn: '15m' }
    );

    const verifyUrl = `${process.env.BACKEND_URL}/api/auth/verify-admin/${token}`;

    const html = `
      <h2>Welcome to GuardianNet Admin Panel</h2>
      <p>Click below to verify your admin email and complete registration:</p>
      <a href="${verifyUrl}">${verifyUrl}</a>
      <p>This link expires in 15 minutes.</p>
    `;

    await transporter.sendMail({
      from: `"GuardianNet" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Admin Account Verification',
      html,
    });

    res.status(200).json({ message: 'Verification email sent to admin. Please check your inbox.' });
  } catch (err) {
    console.error('Register Admin Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Backend: verify-admin route
router.get('/verify-admin/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const decoded = jwt.verify(token, process.env.JWT_EMAIL_SECRET);
    const { email, username, role } = decoded;

    // Check if already verified
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      // Redirect with verified=true to show alert on frontend
      return res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
    }

    // Get from temporary admin collection
    const tempAdmin = await TemporaryAdmin.findOne({ email });
    if (!tempAdmin) {
      return res.status(400).send('Invalid or expired token');
    }

    // Create new user from tempAdmin data
    const newUser = new User({
      username: tempAdmin.username,
      email: tempAdmin.email,
      password: tempAdmin.password,
      role: 'admin',
      isVerified: true,
    });

    await newUser.save();
    await TemporaryAdmin.deleteOne({ email });

    // Redirect with verified=true to show alert on frontend
    return res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (err) {
    console.error('Verify Admin Error:', err);
    return res.status(400).send('Invalid or expired token');
  }
});




module.exports = router;
