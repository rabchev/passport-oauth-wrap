passport-oauth-wrap
===================

OAuth WRAP authentication strategy for Passport and Node.js.

This module lets you use OAuth Web Resource Authorization Profiles, as described in [draft-hardt-oauth-01](http://tools.ietf.org/html/draft-hardt-oauth-01) specifications, to authenticate requests.

OAuth WRAP has been deprecated in favor of OAuth 2.0. This module provides integration with legacy Security Token Services.

Install
-------

    $ npm install passport-oauth-wrap

Usage
-----

See the example.

Note
----

Currently only Simple Web Token is supported. JSON Web Token is partially implemented, but not functional yet.

License
-------

(MIT License)

Copyright (c) 2013 Boyan Rabchev <boyan@rabchev.com>. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
