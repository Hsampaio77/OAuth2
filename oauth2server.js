// const {google} = require('googleapis'),
const people = require('@googleapis/people'),
      crypto = require('crypto'),
      base64url = require('base64url');

const https = require("https"),
    // http = require("http"),
    fs = require("fs"),
    url = require('url'),
    dotenv = require('dotenv'),
    path = require('path'),
    express = require('express');

const app = express();
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

app.set("view engine","ejs");

// Get the configuration values
dotenv.config();
const port = process.env.PORT;
var server = process.env.SERVER;

const args = require('minimist')(process.argv.slice(2));
if (args.h)
    server = args.h;

var keyname = "./certs/" + server + "-key.pem";
var certname = "./certs/" + server + ".pem";
    
console.log("Using key:", keyname);
console.log("Using crt:", certname);
console.log();

const certs = {
    key: fs.readFileSync(keyname),
    cert: fs.readFileSync(certname)
};

/**
 * To use OAuth2 authentication, we need access to a a CLIENT_ID, CLIENT_SECRET, AND REDIRECT_URI.
 * To get these credentials for your application, visit https://console.cloud.google.com/apis/credentials.
 */

/**
 * Create a new OAuth2 client with the keys read from the .env file 
 */
const oauth2Client = new people.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI
);

const peopleV1 = people.people({
    version: 'v1',
    auth: oauth2Client,
});

var state_value = "";

const scopes = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
];

// Dummy url for URL
var dummyhost = 'http://example';

app.get('/', function(req, res) {
    var q = new URL(req.url, dummyhost);
    var action = q.pathname;
    console.log('Received GET request for: ' + action);
    let date = new Intl.DateTimeFormat('en-GB', { dateStyle: 'full', timeStyle: 'long' }).format(new Date());
    res.render('index', {
        date_tag: date,
        message_tag: 'Authorize Access to your Google Account',
    });
});

app.get('/authorize', function(req, res) {
    var q = new URL(req.url, dummyhost);
    var action = q.pathname;
    console.log('Received GET request for: ' + action);

    // Generate redirect URL with params
    state_value = base64url(crypto.randomBytes(16).toString('binary'));
    console.log('State:', state_value);
    const authorizeUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes.join(' '),
        prompt: 'consent',
        state: state_value,
    });
    // Redirect to authorization endpoint
    res.redirect(authorizeUrl);
    console.log('Redirected to:', authorizeUrl);
});

app.get('/retry', async function(req, res) {
    try {
        var q = new URL(req.url, dummyhost);
        var action = q.pathname;
        console.log('Received GET request for: ' + action);
        const result = await peopleV1.people.get({
            resourceName: 'people/me',
            personFields: 'emailAddresses,names,',
        });
        let date = new Date(oauth2Client.credentials.expiry_date);
        let expiryDate = new Intl.DateTimeFormat('en-GB', { dateStyle: 'full', timeStyle: 'long' }).format(date); 
        res.render('retry', {
            date_tag: expiryDate,
            message_tag: 'OAuth2 Query Successful!',
            names_tag: result.data.names[0].displayName,
            email_tag: result.data.emailAddresses[0].value,
        });
    } catch (error) {
        res.render('error', {
            message_tag: `Retry Error: ${error.message}`,
        });
        console.error('Error', error.message); 
    }      
});

app.get('/oauth2callback', async function(req, res) {
    try {
        // console.log(req.body);
        var reqUrl = new URL(req.url, dummyhost);
        var action = reqUrl.pathname;
        console.log('Received GET Callback request for: ' + action);
        console.log('\n', reqUrl);
        const qs = reqUrl.searchParams;

        // Check cross-site request forgery
        var received_state = qs.get('state');
        if (received_state === state_value)
            console.log("State match:", received_state);
        else
            console.log("Warning: state differs!!", received_state, state_value);

        // Exchange the Auth code for Access Tokens 
        var code = qs.get('code');
        console.log('Auth Code:', code);
        // Async call
        var {tokens} = await oauth2Client.getToken(code);
        // eslint-disable-next-line require-atomic-updates
        oauth2Client.credentials = tokens;
        let date = new Date(tokens.expiry_date);
        let expiryDate = new Intl.DateTimeFormat('en-GB', { dateStyle: 'full', timeStyle: 'long' }).format(date); 
        console.log('Tokens received:\n', tokens);

        // Get resource from server
        // Async call
        const result = await peopleV1.people.get({
            resourceName: 'people/me',
            personFields: 'emailAddresses,names,',
        });
        var google_id = result.data.resourceName.split('/')[1];
        // console.log('Google Id:', google_id);
        res.render('display', {
            client_tag: oauth2Client._clientId,
            token_tag: tokens.access_token,
            scope_tag: tokens.scope,
            type_tag: tokens.token_type,
            id_tag: tokens.id_token,
            date_tag: expiryDate,
            message_tag: 'Authorization successful!',
            google_id_tag: google_id,
            names_tag: result.data.names[0].displayName,
            email_tag: result.data.emailAddresses[0].value,
        });   
    } catch (e) {
        console.error(e);
    }
    });

// Fallback route, must be last 
app.get('*', function(req, res) {
    var q = new URL(req.url, dummyhost);
    var filename = (q.pathname == '/'?'index.html':"." + q.pathname);
    console.log('Received request for file: ' + filename);
    // if (!req.body) return res.sendStatus(400);
    res.sendFile(path.join(__dirname, './', filename));
});

const https_server = https.createServer(certs, app).listen(port, () => {
    // var host = https_server.address().address;
    // var port = https_server.address().port;
    console.log('HTTPS server listening on: ', https_server.address());
});
