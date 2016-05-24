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

// var session = require('cookie-session');
//var passport = require('passport');
var crypto = require('crypto');


var OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

var log = bunyan.createLogger({
	name: 'PatChat Web Application'
});


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
//app.use(express.methodOverride()); Do I need this?
app.use(cookieParser());
app.use(expressSession({ secret: 'Something secret', resave: true, saveUninitialized: false }));
app.use(bodyParser.urlencoded({ extended : true }));

//app.use(session({ secret: '1234567890QWERTY' }));

// Passport.js code from https://github.com/Azure-Samples/active-directory-node-webapp-openidconnect
// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
// app.use(app.router); deprecated


var http = require('http').Server(app);
var io = require('socket.io')(http);
var port = process.env.PORT || 3000;

/*
 * AAD code from https://github.com/AzureAD/azure-activedirectory-library-for-nodejs/tree/master/sample
 * 
 * You can override the default account information by providing a JSON file
 * with the same parameters as the parameters variable below.  Either
 * through a command line argument, 'node sample.js parameters.json', or
 * specifying in an environment variable.
 * {
 *   "tenant" : "patricka.onmicrosoft.com",
 *   "authorityHostUrl" : "https://login.windows.net",
 *   "clientId" : "62f6bfcb-dcba-430c-805c-9495ca49453a",
 *   "clientSecret" : "Key from dashboard",
 *   "redirectUri" : "http://localhost:3000/getAToken"
 * }
 */

var AuthenticationContext = require('adal-node').AuthenticationContext;
var parametersFile = process.argv[2] || process.env['ADAL_PARAMETERS_FILE'];

var parameters;
if (parametersFile) {
	var jsonFile = fs.readFileSync(parametersFile);
	if (jsonFile) {
		parameters = JSON.parse(jsonFile);
	} else {
		console.log('File not found, falling back to defaults: ' + parametersFile);
	}
}

if (!parametersFile) {
	parameters = {
		tenant : 'patricka.onmicrosoft.com',
		authorityHostUrl : 'https://login.windows.net',
		clientId : '62f6bfcb-dcba-430c-805c-9495ca49453a',
		clientSecret: 'Key from dashboard',
		redirectUri: 'http://localhost:3000/getAToken'
	};
}

var authorityUrl = parameters.authorityHostUrl + '/' + parameters.tenant;
var redirectUri = parameters.redirectUri;
var resource = '00000002-0000-0000-c000-000000000000';

var templateAuthzUrl = 'https://login.windows.net/' + parameters.tenant + '/oauth2/authorize?response_type=code&client_id=<client_id>&redirect_uri=<redirect_uri>&state=<state>&resource=<resource>';

//Routes

app.get('/', function (req, res) {
	log.info('Redirecting to /login ');
	res.redirect('/login');
});

app.get('/login', function (req, res) {
	console.log(req.cookies);
	res.send('\
<head>\
  <title>Authentication required</title>\
</head>\
<body>\
  <h1><a href="./auth">Login</a></h1>\
</body>\
    ');
});

function createAuthorizationUrl(state) {
	var authorizationUrl = templateAuthzUrl.replace('<client_id>', parameters.clientId);
	authorizationUrl = authorizationUrl.replace('<redirect_uri>', redirectUri);
	authorizationUrl = authorizationUrl.replace('<state>', state);
	authorizationUrl = authorizationUrl.replace('<resource>', resource);
	log.info('authorizationUrl: %s', authorizationUrl);
	return authorizationUrl;
}

// Clients get redirected here in order to create an OAuth authorize url and redirect them to AAD.
// There they will authenticate and give their consent to allow this app access to
// some resource they own.
app.get('/auth', function (req, res) {
	crypto.randomBytes(48, function (ex, buf) {
		var token = buf.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
		
		res.cookie('authstate', token);
		var authorizationUrl = createAuthorizationUrl(token);
		
		res.redirect(authorizationUrl);
	});
});

// After consent is granted AAD redirects here.  The ADAL library is invoked via the
// AuthenticationContext and retrieves an access token that can be used to access the
// user owned resource.
app.get('/getAToken', function (req, res) {
	if (req.cookies.authstate !== req.query.state) {
//		res.send('error: state does not match');
		log.info('/getAToken: authstate %s vs. query.state %s', req.cookies.authstate, req.query.state );
	}
	var authenticationContext = new AuthenticationContext(authorityUrl);
	authenticationContext.acquireTokenWithAuthorizationCode(req.query.code, redirectUri, resource, parameters.clientId, parameters.clientSecret, function (err, response) {
		var message = '';
		if (err) {
			message = 'error: ' + err.message + '\n';
		}
		var userName = response.givenName + ' ' + response.familyName + ' (' + response.userId + ')';
		res.cookie('userName', userName);
		
		if (err) {
			res.send(message);
			return;
		}
		
		// Later, if the access token is expired it can be refreshed.
		authenticationContext.acquireTokenWithRefreshToken(response.refreshToken, parameters.clientId, parameters.clientSecret, resource, function (refreshErr, refreshResponse) {
			if (refreshErr) {
				message += 'refreshError: ' + refreshErr.message + '\n';
			}
		});
		
		res.redirect('/chat');
	});
});

app.get('/chat', passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
//app.get('/chat', passport.authenticate('azuread-openidconnect', { status: false }),
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
