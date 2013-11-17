/*jslint plusplus: true, devel: true, nomen: true, vars: true, node: true, indent: 4, maxerr: 50 */

"use strict";

var express         = require("express"),
    passport        = require("passport"),
    WrapStrategy    = require("passport-oauth-wrap").Strategy,
    loginHandler    = require("passport-oauth-wrap").login,
    ensureLoggedIn  = require("connect-ensure-login").ensureLoggedIn,
    _               = require("lodash"),
    app             = express(),
    config          = {
        // The URL to a Security Token Service.
        authorizeUrl    : "https://sts.somedomain.com/WRAPv0.9/authorize",
        accessTokenUrl  : "https://sts.somedomain.com/WRAPv0.9/access-token",
        callbackUrl     : "http://localhost:3000/login",
        clientId        : "uri:myapp",
        clientSecret    : "6a71767c849ca687733cd43e051f68a8",
        // If the key is simple string then you can assign it directly to symmentricKey property.
        // If the key is binary you have to specify encoding (hex or base64).
        symmetricKey    : {
            value           : "5b9d72c08a7bc34ee855067e55a22b1ba21338dae8eaba9a22bc64bf75dc216a",
            encoding        : "hex"
        }
    },
    claims          = {
        id              : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier",
        username        : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        email           : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email",
        firstName       : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        lastName        : "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        role            : "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    },
    users           = [],
    currId          = 1;

// We have to build and register the user with the supplied claims from the access token.
// The token could be either Simple Web Token or JSON Web Token by specification.
function processToken(token, done) {
    var user = _.find(users, function (item) {
        return item.username === token[claims.username];
    });
    if (!user) {
        user = {
            id          : token[claims.id] || currId++,
            username    : token[claims.username],
            email       : token[claims.email],
            firstName   : token[claims.firstName],
            lastName    : token[claims.lastName]
        };
        var roles = token[claims.role];
        if (!roles) {
            roles = ["guest"];
        } else if (!(roles instanceof Array)) {
            roles = [roles];
        }
        user.roles = roles;
        users.push(user);
    }
    done(null, user);
}

passport.use(new WrapStrategy(config, processToken));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    var user = _.find(users, function (item) {
        return item.id === id;
    });
    if (user) {
        done(null, user);
    } else {
        done(new Error("Invalid user session."));
    }
});

app.use(express.favicon())
    .use(express.bodyParser())
    .use(express.cookieParser())
    .use(express.session({ secret: "keyboard cat" }))
    .use(passport.initialize())
    .use(passport.session())
    .use(app.router);

app.get("/", function (req, res) {
    res.send("hello world");
});

app.get("/protectedPage", ensureLoggedIn("/login"), function (req, res) {
    res.send("hello " + req.user.username);
});

app.get("/protectedService", passport.authenticate("WRAP"), function (req, res) {
    res.json({ message: "hello", user: req.user });
});

// Redirects the user to the STS (issuer) and acquires access token and claims.
app.get("/login", loginHandler(config));

app.listen(3000);
