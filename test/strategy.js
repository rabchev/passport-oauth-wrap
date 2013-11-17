/*jslint plusplus: true, devel: true, nomen: true, vars: true, node: true, es5: true, indent: 4, maxerr: 50 */
/*global describe, it */

"use strict";

var expect          = require("chai").expect,
    WrapStrategy    = require("../lib").Strategy;

describe("WRAP Strategy", function () {
    it("constructor should require options", function () {
        expect(function () {
            var strategy;
            strategy = new WrapStrategy();
        }).to.throw("OAuthWrapStrategy requires a verify callback.");
    });
});
