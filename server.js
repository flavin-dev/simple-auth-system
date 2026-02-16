const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

const app = express();

// 1. Database Connection
mongoose.connect('mongodb://127.0.0.1:27017/simpleAuthDB')
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.error(err));

// 2. Middleware Configuration
app.set('view engine', 'ejs'); // Set EJS as templating engine
app.use(express.urlencoded({ extended: false })); // Parse form data
app.use(session({
    secret: 'secretKey', // Change this for production
    resave: false,
    saveUninitialized: false
}));

// 3. Authentication Middleware (Protects the Dashboard)
const checkAuth = (req, res, next) => {
    if (req.session.userId) {
        return next(); // User is logged in, proceed
    }
    res.redirect('/login'); // User is not logged in, redirect
};

// --- ROUTES ---

// Home/Root -> Redirect to Login
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Registration Routes
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.send("User already exists. <a href='/register'>Try again</a>");

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save new user
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.redirect('/login');
    } catch (err) {
        res.status(500).send("Error registering user");
    }
});

// Login Routes
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = await User.findOne({ username });
        if (!user) return res.send("User not found");

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.send("Invalid credentials");

        // Set session
        req.session.userId = user._id;
        req.session.username = user.username;
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send("Server error");
    }
});

// Dashboard Route (Protected)
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('dashboard', { user: req.session.username });
});

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Start Server
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});