/*jslint plusplus: true, devel: true, nomen: true, vars: true, node: true, indent: 4, maxerr: 50 */

"use strict";

/**
 * Module dependencies.
 */
var Strategy    = require('./strategy'),
    login       = require("./login");


/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;

/**
 * Expose login middle-ware
 */
exports.login = login;
