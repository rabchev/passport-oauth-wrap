/*jslint plusplus: true, devel: true, nomen: true, vars: true, node: true, indent: 4, maxerr: 50 */

"use strict";

/**
 * Module dependencies.
 */
var passport        = require("passport-strategy"),
    queryString     = require("querystring"),
    crypto          = require("crypto"),
    https           = require("https"),
    util            = require("util"),
    url             = require("url");


/**
 * Creates an instance of `Strategy`.
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    if (!verify) {
        throw new TypeError("OAuthWrapStrategy requires a verify callback.");
    }
    if (!options) {
        throw new TypeError("OAuthWrapStrategy requires a options parameter.");
    }

    passport.Strategy.call(this);

    this.name           = "WRAP";
    this._verify        = verify;
    this._issuerUri     = options.issuerUri;
    this._clientId      = options.clientId;
    this._clientSecret  = options.clientSecret;
    this._symmetricKey  = options.symmetricKey;
    this._audience      = options.audience;
    if (options.scope) {
        this._scope = (Array.isArray(options.scope)) ? options.scope : [options.scope];
    }
    this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP WRAP authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req) {
    var that = this;

    function verified(err, user, info) {
        if (err) {
            return that.error(err);
        }
        if (!user) {
            if (typeof info === "string") {
                info = {
                    message: info
                };
            }
            info = info || {};
            return that.fail(that._challenge("invalid_token", info.message));
        }
        that.success(user, info);
    }

    function verify(err, token) {
        if (err) {
            return that.fail(that._challenge("invalid_token", err));
        }

        if (that._passReqToCallback) {
            that._verify(req, token, verified);
        } else {
            that._verify(token, verified);
        }
    }

    this._getRawToken(req, function (rawToken) {
        if (!rawToken) {
            return that.fail(that._challenge());
        }
        var idx = rawToken.indexOf("&HMACSHA256=");
        if (idx !== -1) {
            that._validateSWT(rawToken, idx, verify);
        } else {
            that._validateJWT(rawToken, verify);
        }
    });
};

Strategy.prototype._base64urlUnescape = function (str) {
    str += new Array(5 - str.length % 4).join('=');
    return str.replace(/\-/g, '+').replace(/_/g, '/');
};

Strategy.prototype._base64urlDecode = function (str) {
    return new Buffer(this._base64urlUnescape(str), 'base64').toString();
};

Strategy.prototype._validateSWT = function (rawToken, idx, callback) {
    var body        = rawToken.substr(0, idx),
        signature   = decodeURIComponent(rawToken.substr(idx + 12)),
        hash        = crypto.createHmac("sha256", this._symmetricKey).update(body, "utf8").digest("base64"),
        token,
        dDate,
        seconds;

    if (hash !== signature) {
        return callback("Invalid signature.");
    }

    token = queryString.parse(body);
    dDate = new Date();
    seconds = Date.UTC(dDate.getUTCFullYear(),
                       dDate.getUTCMonth(),
                       dDate.getUTCDate(),
                       dDate.getUTCHours(),
                       dDate.getUTCMinutes(),
                       dDate.getUTCSeconds(),
                       dDate.getUTCMilliseconds()) / 1000;
    if (parseInt(token.ExpiresOn, 10) <= seconds) {
        return callback("Token expired.");
    }
    if (this._audience) {
        if (token.Audience instanceof Array && token.Audience.indexOf(this._audience) === -1) {
            return callback("Invalid token audience.");
        } else if (this._audience !== token.Audience) {
            return callback("Invalid token audience.");
        }
    }
    callback(null, token);
};

Strategy.prototype._validateJWT = function (rawToken, callback) {
    var segments,
        header,
        body,
        signature;

    try {
        segments = rawToken.split(".");
        if (segments.length !== 3) {
            return callback("Invalid JWT format.");
        }
        header = JSON.parse(this._base64urlDecode(segments[0]));
        body = JSON.parse(this._base64urlDecode(segments[1]));
        signature = this._base64urlDecode(segments[2]);
        // TODO: validate signature, expiration and audience;
        callback(null, body);
    } catch (err) {
        callback(err.message);
    }
};

Strategy.prototype._getRawToken = function (req, callback) {
    var token;

    if (req.query) {
        if (req.query.wrap_verification_code) {
            this._requestAccessToken(req, callback);
        } else if (req.query.wrap_error_reason) {
            this.fail(req.query.wrap_error_reason);
        }
        return;
    }

    if (req.headers && req.headers.authorization) {
        var regExp = /(?:^WRAP\s+access_token\s*=\s*"?)([^\s\"]+?)(?:"?\s*$)/gi,
            match = regExp.exec(req.headers.authorization);

        if (match) {
            token = match[1];
        } else {
            return this.fail(400);
        }
    }

    if (req.body && req.body.access_token) {
        if (token) { return this.fail(400); }
        token = req.body.access_token;
    }

    if (req.query && req.query.access_token) {
        if (token) { return this.fail(400); }
        token = req.query.access_token;
    }

    callback(token);
};

Strategy.prototype._requestAccessToken = function (req, callback) {
    if (!req.session) {
        throw new Error("OAuthWrapStrategy requires session support when requesting access token. Did you forget app.use(express.session(...))?");
    }

    if (req.session.wrapClientState && req.session.wrapClientState !== req.query.wrap_client_state) {
        return this.fail(400, "Invalid client state.");
    }

    var opts        = url.parse(this._issuerUri),
        payload     = {
            wrap_client_id          : this._clientId,
            wrap_client_secret      : this._clientSecret,
            wrap_verification_code  : req.query.wrap_verification_code,
            wrap_callback           : req.session.wrapCallback
        },
        that        = this,
        clientReq;

    payload = queryString.stringify(payload);

    opts.port = 443;
    opts.method = "POST";
    opts.headers = {
        "Content-Type"      : "application/x-www-form-urlencoded",
        "Content-Length"    : payload.length
    };

    clientReq = https.request(opts, function (res) {
        var result = "";

        res.setEncoding("utf8");
        res.on("data", function (data) {
            result += data;
        });
        if (res.statusCode === 200) {
            if (res.headers["content-length"]) {
                res.on("end", function () {
                    var pRes = queryString.parse(result);
                    callback(pRes.wrap_access_token);
                });
            } else {
                that.fail(500, "Obtaining access token failed: empty response");
            }
        } else {
            if (res.headers["content-length"]) {
                res.on("end", function () {
                    that.fail(500, "Obtaining access token failed with error: " + result);
                });
            } else {
                that.fail(500, "Obtaining access token failed with status code: " + res.statusCode);
            }
        }
    });

    clientReq.on("error", function (err) {
        that.fail(500, err.message);
    });

    clientReq.write(payload);
    clientReq.end();
};

/**
 * Build authentication challenge.
 *
 * @api private
 */
Strategy.prototype._challenge = function (code, desc, uri) {
    var challenge = "WRAP ";
    if (this._scope) {
        challenge += 'scope="' + this._scope.join(' ') + '"';
    }
    if (code) {
        if (this._scope) {
            challenge += ", ";
        }
        challenge += 'error="' + code + '"';
    }
    if (desc && desc.length) {
        if (this._scope || code) {
            challenge += ", ";
        }
        challenge += 'error_description="' + desc + '"';
    }
    if (uri && uri.length) {
        if (this._scope || code || (desc && desc.length)) {
            challenge += ", ";
        }
        challenge += 'error_uri="' + uri + '"';
    }

    return challenge;
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
