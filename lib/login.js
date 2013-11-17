/*jslint plusplus: true, devel: true, nomen: true, vars: true, node: true, indent: 4, maxerr: 50 */

"use strict";

var queryString     = require("querystring"),
    passport        = require("passport"),
    crypto          = require("crypto");

module.exports = function (opts) {
    return function (req, res, next) {
        passport.authenticate("WRAP", function (err, user) {
            if (err) {
                return next(err);
            }
            if (!user) {
                var query = {
                    wrap_client_id: opts.clientId,
                    wrap_callback: opts.callbackUrl
                };
                if ((opts.useClientState || true)) {
                    query.wrap_client_state = crypto.randomBytes(16).toString("hex");
                    req.session.wrapClientState = query.wrap_client_state;
                }
                return res.redirect(opts.authorizeUrl + "?" + queryString.stringify(query));
            }
            req.logIn(user, function (err) {
                if (err) {
                    return next(err);
                }
                if (req.session && req.session.returnTo) {
                    var url = req.session.returnTo;
                    delete req.session.returnTo;
                    return res.redirect(url);
                }
                if (opts.successRedirect) {
                    return res.redirect(opts.successRedirect);
                }
                next();
            });
        })(req, res, next);
    };
};
