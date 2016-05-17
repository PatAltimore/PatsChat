'use strict';

var express = require('express');
var fs = require('fs');

var logger = require('connect-logger');
var cookieParser = require('cookie-parser');
var session = require('cookie-session');
var crypto = require('crypto');
var passport = require('passport');
var OIDCBearerStrategy = require('passport-azure-ad').BearerStrategy;
var config = require('./config');

var AuthenticationContext = require('adal-node').AuthenticationContext;

var app = express();
app.use(logger());
app.use(cookieParser('a deep secret'));
app.use(session({ secret: '1234567890QWERTY' }));

// Passport.js code from https://github.com/Azure-Samples/active-directory-node-webapi
// Let's start using Passport.js

app.use(passport.initialize()); // Starts passport
app.use(passport.session()); // Provides session support 

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

// We pass these options in to the ODICBearerStrategy.

var options = {
	// The URL of the metadata document for your app. We will put the keys for token validation from the URL found in the jwks_uri tag of the in the metadata.
	identityMetadata: config.creds.identityMetadata,
	issuer: config.creds.issuer,
	audience: config.creds.audience //,
//	validateIssuer: config.creds.validateIssuer,
//	passReqToCallback: config.creds.passReqToCallback,
//	loggingLevel: config.creds.loggingLevel
};

/**
/*
/* Calling the OIDCBearerStrategy and managing users
/*
/* Passport pattern provides the need to manage users and info tokens
/* with a FindorCreate() method that must be provided by the implementor.
/* Here we just autoregister any user and implement a FindById().
/* You'll want to do something smarter.
**/

 var findById = function (id, fn) {
	for (var i = 0, len = users.length; i < len; i++) {
		var user = users[i];
		if (user.sub === id) {
			log.info('Found user: ', user);
			return fn(null, user);
		}
	}
	return fn(null, null);
};


var oidcStrategy = new OIDCBearerStrategy(options,
    function (token, done) {
		findById(token.sub, function (err, user) {
			if (err) {
				return done(err);
			}
			if (!user) {
				// "Auto-registration"
				// User was added automatically as they were new. Their sub is: token.sub
				users.push(token);
				owner = token.sub;
				return done(null, token);
			}
			owner = token.sub;
			return done(null, user, token);
		});
	}
);

passport.use(OIDCBearerStrategy);

app.get('/', function (req, res) {
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
		res.send('error: state does not match');
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

app.get('/chat', passport.authenticate('azuread-openidconnect', { session: false }),
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
