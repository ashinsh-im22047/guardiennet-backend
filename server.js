// backend/server.js

const express = require('express');
const cors = require('cors');
require('dotenv').config();
const authRoutes = require('./routes/authRoutes'); // Auth routes file
const connectDB = require('./config/db');

const app = express();
app.use(express.json());
// Middleware
app.use(cors());
 // Needed to parse JSON body from requests

// Routes
app.use('/api/auth', authRoutes);

// Default Route
app.get('/', (req, res) => {
  res.send('✅ API Running');
});

// Start server after DB connection
const startServer = async () => {
  try {
    await connectDB();
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`✅ Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
};

startServer();
