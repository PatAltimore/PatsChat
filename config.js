 exports.creds = {

	 returnURL: 'http://localhost:3000/auth/openid/return',
     identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration', 
	clientID: '62f6bfcb-dcba-430c-805c-9495ca49453a',
	clientSecret: 'Ykca6n2QMLx/LnGJrQbULq2Qxyhhc2ZkecV1bNqZzhc=',
	tenantName: 'patricka.onmicrosoft.com',
	validateIssuer: true, // if you have validation on, you cannot have users from multiple tenants sign in to your server
	passReqToCallback: false,
	skipUserProfile: true, // for AzureAD should be set to true.
	responseType: 'id_token code', // for login only flows use id_token. For accessing resources use `id_token code`
	responseMode: 'query', // For login only flows we should have token passed back to us in a POST
     loggingLevel: 'info' // valid are 'info', 'warn', 'error'. Error always goes to stderr in Unix.

 };

