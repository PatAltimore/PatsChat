'use strict';

var express = require('express');
var fs = require('fs');

var logger = require('connect-logger');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');
var bodyParser = require('body-parser');
var passport = require('passport');
var util = require('util');
var bunyan = require('bunyan');
var config = require('./config');

var OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

var log = bunyan.createLogger({
	name: 'PatChat Web Application'
});

// Passport.js code from https://github.com/Azure-Samples/active-directory-node-webapp-openidconnect

// Passport session setup. (Section 2)

//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function (user, done) {
	done(null, user.email);
});

passport.deserializeUser(function (id, done) {
	findByEmail(id, function (err, user) {
		done(err, user);
	});
});

// array to hold logged in users
var users = [];

var findByEmail = function (email, fn) {
	for (var i = 0, len = users.length; i < len; i++) {
		var user = users[i];
		log.info('we are using user: ', user);
		if (user.email === email) {
			return fn(null, user);
		}
	}
	return fn(null, null);
};

// Use the OIDCStrategy within Passport. (Section 2) 
// 
//   Strategies in passport require a `validate` function, which accept
//   credentials (in this case, an OpenID identifier), and invoke a callback
//   with a user object.
passport.use(new OIDCStrategy({
	callbackURL: config.creds.returnURL,
	realm: config.creds.realm,
	clientID: config.creds.clientID,
	clientSecret: config.creds.clientSecret,
	oidcIssuer: config.creds.issuer,
	identityMetadata: config.creds.identityMetadata,
	skipUserProfile: config.creds.skipUserProfile,
	responseType: config.creds.responseType,
	responseMode: config.creds.responseMode
},
  function (iss, sub, profile, accessToken, refreshToken, done) {
	if (!profile.email) {
		return done(new Error("No email found"), null);
	}
	// asynchronous verification, for effect...
	process.nextTick(function () {
		findByEmail(profile.email, function (err, user) {
			if (err) {
				return done(err);
			}
			if (!user) {
				// "Auto-registration"
				users.push(profile);
				return done(null, profile);
			}
			return done(null, user);
		});
	});
}
));



// configure Express (Section 2)

var app = express();
app.use(logger());
app.use(cookieParser());
app.use(expressSession({ secret: 'Something secret', resave: true, saveUninitialized: false }));
app.use(bodyParser.urlencoded({ extended : true }));

// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());

 app.set('views', __dirname + '/views');
 app.set('view engine', 'ejs');
 
var http = require('http').Server(app);
var io = require('socket.io')(http);
var port = process.env.PORT || 3000;

//Routes

app.get('/', function (req, res) {
	res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('Login was called in the Sample');
    res.redirect('/');
});

// POST /auth/openid
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in OpenID authentication will involve redirecting
//   the user to their OpenID provider.  After authenticating, the OpenID
//   provider will redirect the user back to this application at
//   /auth/openid/return
app.get('/auth/openid',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('Authentication was called in the Sample');
    res.redirect('/');
  });

// GET /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('We received a return from AzureAD.');
	
	// Save user name
	var userName = req.user.displayName + ' (' + req.user.email + ')';
	res.cookie('userName', userName);
		
	res.sendFile(__dirname + '/index.html');
  });

// GET /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.post('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('We received a post return from AzureAD.');
	
		// Save user name
	var userName = req.user.displayName + ' (' + req.user.email + ')';
	res.cookie('userName', userName);
	
	res.sendFile(__dirname + '/index.html');    
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.get('/chat', passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
//app.get('/chat', 
	function (req, res) {
	res.sendFile(__dirname + '/index.html');
});

io.on('connection', function (socket) {
	
	socket.on('chat message', function (msg) {
		io.emit('chat message', msg);
	});
});
http.listen(port, function () {
	console.log('listening on ' + port);
});

// Simple route middleware to ensure user is authenticated. (Section 4)

//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
