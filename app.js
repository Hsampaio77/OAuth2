const express = require('express');
const app = express();
const session = require('express-session');

const passport = require('passport');
require('./services/passport');

const {port, https, certs} = require('./services/https');

/*  VIEW ENGINE */
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 1
  }
}));

app.use(passport.initialize());
app.use(passport.session());
require('./routes/authRoutes')(app);

const https_server = https.createServer(certs, app).listen(port, () => {
  console.log('HTTPS server listening on: ', https_server.address());
});
