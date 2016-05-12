 exports.creds = {
     clientID: '62f6bfcb-dcba-430c-805c-9495ca49453a',
     audience: 'https://patricka.onmicrosoft.com/patschat',
    // you cannot have users from multiple tenants sign in to your server unless you use the common endpoint
  // example: https://login.microsoftonline.com/common/.well-known/openid-configuration
     identityMetadata: 'https://login.microsoftonline.com/62f6bfcb-dcba-430c-805c-9495ca49453a/.well-known/openid-configuration', 
     validateIssuer: true, // if you have validation on, you cannot have users from multiple tenants sign in to your server
     passReqToCallback: false,
     loggingLevel: 'info' // valid are 'info', 'warn', 'error'. Error always goes to stderr in Unix.

 };

