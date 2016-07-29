/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
 
 /* eslint-disable no-new */

 'use restrict';

var chai = require('chai');
var url = require('url');
var OIDCStrategy = require('../../lib/index').OIDCStrategy;
var stateHandler = require('../../lib/stateHandler');

chai.use(require('chai-passport-strategy'));

// Mock options required to create a OIDC strategy
var options = {
    callbackURL: 'http://www.example.com/returnURL',
    clientID: 'my_client_id',
    clientSecret: 'my_client_secret',
    identityMetadata: 'https://www.example.com/metadataURL',
    skipUserProfile: true,
    responseType: 'id_token',
    responseMode: 'form_post',
    validateIssuer: true,
    passReqToCallback: false,
    sessionKey: 'my_key'    //optional sessionKey
};

var testStrategy = new OIDCStrategy(options, function(profile, done) {});

// Mock `configure`
// `configure` is used to calculate and set the variables required by oauth2, 
// here we just provide the variable values.
testStrategy.configure = function(identifier, done) {
  var opt = {           
    clientID: options.clientID,
    clientSecret: options.clientSecret,
    authorizationURL: 'https://www.example.com/authorizationURL',
    tokenURL: 'https://www.example.com/tokenURL'
  };
  done(null, opt);
};

// Mock `setOptions`
// `setOptions` is used to read and save the metadata, we don't need this in test 
testStrategy.setOptions = function(options, metadata, cachekey, next) { return next();};


describe('OIDCStrategy state validation', function() {
  var request, redirect_url;

  // we can provide a state value to `authenticate`, or it will generate one 
  // automatically. The following are examples of `authenticate_option`:
  //   authenticate_option = {}
  //   authenticate_option = {state: 'xxx'}
  var testPrepare = function(authenticate_option) {
  	return function(done) {
  		chai.passport
  		  .use(testStrategy)
  		  .redirect(function(u) {
  		  	redirect_url = u;
  		  	done();
  		  })
  		  .req(function(req) {
  		  	request = req;
  		  	req.session = {};
  		  	req.query = {};
  		  })
  		  .authenticate(authenticate_option);
  	};
  };

  describe('with automatically generated state', function() {
  	before(testPrepare({}));

  	it('should be redirected', function() {
  		var u = url.parse(redirect_url, true);
  		chai.expect(u.query.state).to.have.length(24);
  	});

  	it('should save state in session', function() {
  		var u = url.parse(redirect_url, true);
  		chai.expect(request.session[testStrategy._key].state).to.have.length(24);
  		chai.expect(request.session[testStrategy._key].state).to.equal(u.query.state);
  	});
  });

  describe('with provided state', function() {
  	var my_state = 'my_awesome_fanstatic_state';
  	before(testPrepare({state: my_state}));

  	it('should be redirected', function() {
  		var u = url.parse(redirect_url, true);
  		chai.expect(u.query.state).to.equal(my_state);
  	});

  	it('should save state in session', function() {
  		var u = url.parse(redirect_url, true);
  		chai.expect(request.session[testStrategy._key].state).to.equal(u.query.state);
  	});
  });

});
