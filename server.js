require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // ✅ Added for serving index.html

const app = express();
const port = 3000;

// Use a secret key for JWT token generation. In a real app, this should be in an environment variable.
require('dotenv').config();
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;


// Middleware to parse JSON bodies and allow cross-origin requests
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

// ✅ Serve static files (index.html, CSS, JS, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Successfully connected to MongoDB!'))
  .catch(err => {
    console.error('Could not connect to MongoDB:', err);
    // Exit process if database connection fails
    process.exit(1);
  });

// Define Mongoose Schemas
const userSchema = new mongoose.Schema({
  accountName: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

const bookingSchema = new mongoose.Schema({
  date: {
    type: String,
    required: true
  },
  time: {
    type: String,
    required: true
  },
  service: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
});

// Create Mongoose Models
const User = mongoose.model('User', userSchema);
const Booking = mongoose.model('Booking', bookingSchema);

// === API Routes ===

// Sign-up route to create a new user.
app.post('/signup', async (req, res) => {
  try {
    const { accountName, email, password } = req.body;

    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists with this email.' });
    }

    // Hash the password for security
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the new user in the database
    const newUser = await User.create({
      accountName,
      email,
      password: hashedPassword
    });

    res.status(201).json({ message: 'Account created successfully!', userId: newUser._id });
  } catch (error) {
    console.error('Error during sign-up:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Sign-in route to authenticate a user and provide a token.
app.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // If credentials are valid, generate a JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email, accountName: user.accountName },
      JWT_SECRET,
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.json({ message: 'Sign-in successful!', token });
  } catch (error) {
    console.error('Error during sign-in:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Middleware to protect authenticated routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Get the token from "Bearer TOKEN"

  if (token == null) {
    return res.status(401).json({ message: 'Authentication token required.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    req.user = user; // Add the user payload to the request
    next();
  });
};

// Protected route to fetch the user's account name
app.get('/fetch-account-name', authenticateToken, (req, res) => {
  try {
    const { accountName } = req.user;
    res.json({ accountName });
  } catch (error) {
    console.error('Error fetching account name:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Protected route to create a new booking
app.post('/bookings', authenticateToken, async (req, res) => {
  try {
    const { date, time, service } = req.body;
    const userId = req.user.userId;

    const newBooking = await Booking.create({
      date,
      time,
      service,
      userId
    });

    res.status(201).json({ message: 'Booking created successfully!', booking: newBooking });
  } catch (error) {
    console.error('Error creating booking:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Protected route to fetch all bookings for the authenticated user
app.get('/bookings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const bookings = await Booking.find({ userId }).sort({ date: 1, time: 1 });
    res.json(bookings);
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// ✅ Root route now serves index.html automatically
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
