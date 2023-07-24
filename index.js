// index.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key'; // Replace this with your actual secret key
// Sample user data (Replace this with a real database in a production app)
const users = [];

// Middleware to parse request bodies
app.use(bodyParser.json());

// Registration route
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  // Check if the username is already taken
  if (users.find((user) => user.username === username)) {
    return res.status(409).json({ message: 'Username already exists.' });
  }

  // Hash the password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).json({ message: 'Error hashing password.' });
    }

    const newUser = {
      id: users.length + 1,
      username,
      password: hash,
    };

    users.push(newUser);
    res.status(201).json({ message: 'Registration successful.' });
  });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  // Compare the hashed password
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Create a JWT token
    const token = jwt.sign({ userId: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
    res.json({ message: 'Login successful.', token });
  });
});

// Middleware to protect routes with JWT authorization
function verifyJWT(req, res, next) {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ message: 'Missing token' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    // Store the decoded payload in the request object for further use
    req.user = decoded;
    next();
  });
}

// Example of using the middleware to protect a route
app.get('/protected', verifyJWT, (req, res) => {
  res.json({ message: 'This is a protected route!', user: req.user });
});

// Route to get all registered users
app.get('/users', (req, res) => {
    // In a real-world application, you should handle pagination and limit the number of users returned
    res.json(users);
  });
  
  // Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
