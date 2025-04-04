const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();

const saltRounds = 10;

app.use(express.urlencoded({ extended: true }));

// Firebase setup
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const serviceAccount = require("./key.json");

initializeApp({
    credential: cert(serviceAccount)
});
const db = getFirestore();

// Session setup
app.use(session({
    secret: 'your_secret_key', // Use a strong secret in production
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Signup with password hashing
app.post('/signupSubmit', (req, res) => {
    const { Name, dob, username, password } = req.body;

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            return res.send("Hashing Error: " + err.message);
        }

        db.collection("users").add({
            Name: Name || "Unknown",
            dob: dob || "N/A",
            username: username,
            password: hash
        }).then(() => {
            res.redirect('/login');
        }).catch(err => {
            res.send("Signup Error: " + err.message);
        });
    });
});

// Login with password comparison
app.post('/loginSubmit', (req, res) => {
    const { username, password } = req.body;

    db.collection("users")
        .where("username", "==", username)
        .get()
        .then((snapshot) => {
            if (!snapshot.empty) {
                const doc = snapshot.docs[0];
                const data = doc.data();

                bcrypt.compare(password, data.password, (err, result) => {
                    if (result) {
                        req.session.user = {
                            username: username,
                            name: data.Name,
                            dob: data.dob
                        };
                        res.redirect('/dashboard');
                    } else {
                        res.send("Login failed: Incorrect password.");
                    }
                });
            } else {
                res.send("Login failed: Username not found.");
            }
        })
        .catch(err => {
            res.send("Login Error: " + err.message);
        });
});

// Dashboard (protected)
app.get('/dashboard', (req, res) => {
    if (req.session.user) {
        res.render('dashboard', {
            username: req.session.user.username,
            about: {
                Name: req.session.user.name,
                dob: req.session.user.dob
            }
        });
    } else {
        res.redirect('/login');
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.send("Logout Error");
        }
        res.redirect('/');
    });
});

// Server
app.listen(8000, () => {
    console.log('Server running at http://localhost:8000');
});
