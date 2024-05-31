//Author: James Ingrassia
// Last update 5/31/24
//This is a REST API
// Make a app server and login


// download bcrypt
// console code for that (npm install express bcryptjs jsonwebtoken)
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your_jwt_secret'; //its a secret

let users = []; // In-memory store for user data

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

// Make status endpoint
app.get('/status', (req, res) => {
  const status = { status: 'running' };
  res.json(status);
});
// server is running
// Make registration endpoint 
app.post('/register', async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
      }
  
      const existingUser = users.find(user => user.username === username);
      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      users.push({ username, password: hashedPassword });
  
      res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Error registering user' });
    }
});
  

// Make Login endpoint?
//research this
// login checks credentials and returns a jwt token if valid
app.post('/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
      }
  
      const user = users.find(user => user.username === username);
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }
  
      const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
      const decodedToken = jwt.decode(token);
      console.log('Token:', token);
      console.log('Decoded Token:', decodedToken);
  
      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Error logging in user' });
    }
});

// I have to authenticate and make middleware 
// checks for jwt token and if its valid
const authenticate = (req, res, next) => {
    const authHeader = req.header('Authorization');
    console.log('Authorization Header:', authHeader);
  
    const token = authHeader && authHeader.split(' ')[1];
    console.log('Token:', token);
  
    if (!token) {
      return res.status(401).json({ message: 'Access denied' });
    }
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      console.log('Decoded Token:', decoded);
      next();
    } catch (err) {
      console.error('Token verification failed:', err);
      res.status(400).json({ message: 'Invalid token' });
    }
};
  

// Protected endpoint example using jwt middle ware
app.get('/protected', authenticate, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});
//I have to make a crud file too, check stickies for notes on how to make it
// R I have to read it
// Read all users 
app.get('/users', (req, res) => {
    res.json(users);
});
// Read a single user by username
app.get('/users/:username', (req, res) => {
    const user = users.find(u => u.username === req.params.username);
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: 'User not found' });
    }
});
//U i have to update it
// Update a user by username
app.put('/users/:username', async (req, res) => {
    const { username } = req.params;
    const { newPassword } = req.body;
    const user = users.find(u => u.username === username);
  
    if (user) {
      user.password = await bcrypt.hash(newPassword, 10);
      res.json({ message: 'User password updated successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
});
//D i have to delete it
// Delete a user by username
app.delete('/users/:username', (req, res) => {
    const { username } = req.params;
    const userIndex = users.findIndex(u => u.username === username);
  
    if (userIndex !== -1) {
      users.splice(userIndex, 1);
      res.json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
});
// Handle errors
app.use((req, res, next) => {
    res.status(404).json({ error: 'Not Found' });
});
// i get iat and exp out i could add logging statements
// later
