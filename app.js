const express = require('express');
const bodyParser = require('body-parser');

const app = express();

// middleware
app.use(bodyParser.urlencoded({ extended: true }));

// set view engine
app.set('view engine', 'ejs');

// environment variables
const PORT = process.env.PORT || 3000;
const SERVER_NAME = process.env.SERVER_NAME || "Server";

// login page
app.get('/', (req, res) => {
    res.render('login');
});

// handle login
app.post('/login', (req, res) => {
    const username = req.body.username;
    res.redirect('/dashboard/' + username);
});

// dashboard
app.get('/dashboard/:user', (req, res) => {
    res.render('dashboard', {
        user: req.params.user,
        server: SERVER_NAME
    });
});

// health check
app.get('/health', (req, res) => {
    res.status(200).send("OK");
});

// start server
app.listen(PORT, () => {
    console.log(`${SERVER_NAME} running on port ${PORT}`);
});