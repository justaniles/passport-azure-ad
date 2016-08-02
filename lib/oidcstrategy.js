/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the 'Software'), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

/* eslint no-underscore-dangle: 0 */

const async = require('async');
const cacheManager = require('cache-manager');
const _ = require('lodash');
const jws = require('jws');
const jwt = require('jsonwebtoken');
const OAuth2 = require('oauth').OAuth2;
const objectTransform = require('oniyi-object-transform');
const passport = require('passport');
const querystring = require('querystring');
const url = require('url');
const util = require('util');

const InternalOAuthError = require('./errors/internaloautherror');
const InternalOpenIDError = require('./errors/internalopeniderror');
const Log = require('./logging').getLogger;
const Metadata = require('./metadata').Metadata;
const nonceHandler = require('./nonceHandler');
const setup = require('./oidcsetup');
const stateHandler = require('./stateHandler');
const utils = require('./aadutils');
const Validator = require('./validator').Validator;

// global variable definitions
const log = new Log('AzureAD: OIDC Passport Strategy');

const memoryCache = cacheManager.caching({ store: 'memory', max: 3600, ttl: 1800 /* seconds */ });
const ttl = 1800; // 30 minutes cache
// Note: callback is optional in set() and del().

function makeProfileObject(src, raw) {
  return {
    // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
    // 'sub' key was named 'user_id'.  Many providers still use the old
    // key, so fallback to that.
    id: src.sub || src.oid || src.user_id,
    displayName: src.name,
    name: {
      familyName: src.family_name,
      givenName: src.given_name,
      middleName: src.middle_name,
    },
    email: src.upn || src.preferred_username || src.oid,
    _raw: raw,
    _json: src,
  };
}

function onProfileLoaded(strategy, args) {
  function verified(err, user, info) {
    if (err) {
      return strategy.error(err);
    }
    if (!user) {
      return strategy.fail(info);
    }
    return strategy.success(user, info);
  }

  const verifyArityArgsMap = {
    8: 'iss sub profile jwtClaims accessToken refreshToken params',
    7: 'iss sub profile accessToken refreshToken params',
    6: 'iss sub profile accessToken refreshToken',
    4: 'iss sub profile',
    3: 'iss sub',
  };

  const arity = (strategy._passReqToCallback) ? strategy._verify.length - 1 : strategy._verify.length;
  let verifyArgs = [args.profile, verified];

  if (verifyArityArgsMap[arity]) {
    verifyArgs = verifyArityArgsMap[arity]
      .split(' ')
      .map((argName) => {
        return args[argName];
      })
      .concat([verified]);
  }

  if (strategy._passReqToCallback) {
    verifyArgs.unshift(args.req);
  }

  return strategy._verify.apply(strategy, verifyArgs);
}

/**
 * `Strategy` constructor.
 *
 * The OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  passport.Strategy.call(this);

  /*
   *  Caution when you want to change these values in the member functions of
   *  Strategy, don't use `this`, since `this` points to a subclass of `Strategy`.
   *  To get `Strategy`, use Object.getPrototypeOf(this).
   *  
   *  More comments at the beginning of `Strategy.prototype.authenticate`. 
   */
  this._options = options;
  this.name = 'azuread-openidconnect';
  this._verify = verify;
  this._configurers = [];
  this._skipUserProfile = !!options.skipUserProfile;
  this._passReqToCallback = !!options.passReqToCallback;

  /* When a user is authenticated for the first time, passport adds a new field
   * to req.session called 'passport', and puts a 'user' property inside (or your
   * choice of field name and property name if you change passport._key and 
   * passport._userProperty values). req.session['passport']['user'] is usually 
   * user_id (or something similar) of the authenticated user to reduce the size
   * of session. When the user logs out, req.session['passport']['user'] will be
   * destroyed. Any request between login (when authenticated for the first time)
   * and logout will have the 'user_id' in req.session['passport']['user'], so
   * passport can fetch it, find the user object in database and put the user
   * object into a new field: req.user. Then the subsequent middlewares and the 
   * app can use the user object. This is how passport keeps user authenticated. 
   *
   * For state validation, we also take advantage of req.session. we create a new
   * field: req.session[sessionKey], where the sessionKey is our choice (in fact, 
   * this._key, see below). When we send a request with state, we put state into
   * req.session[sessionKey].state; when we expect a request with state in query
   * or body, we compare the state in query/body with the one stored in 
   * req.session[sessionKey].state, and then destroy req.session[sessionKey].state.
   * User can provide a state by using `authenticate(Strategy, {state: 'xxx'})`, or
   * one will be generated automatically. This is essentially how passport-oauth2
   * library does the state validation, and we use the same way in our library. 
   *
   * request structure will look like the following. In real request some fields
   * might not be there depending on the purpose of the request.
   *
   *    request ---|--- sessionID
   *               |--- session --- |--- ...
   *               |                |--- 'passport' ---| --- 'user': 'user_id etc'
   *               |                |---  sessionKey---| --- state: 'xxx'            
   *               |--- ...
   *               |--- 'user':  full user info
   */
  this._key = options.sessionKey || ('OIDC: ' + options.callbackURL);

  if (!options.identityMetadata) {
    // default value should be https://login.microsoftonline.com/common/.well-known/openid-configuration
    log.error('OIDCStrategy requires a metadata location that contains cert data for RSA and ECDSA callback.');
    throw new TypeError(`OIDCStrategy requires a metadata location that contains cert data for RSA and ECDSA callback.`);
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  // warn about validating the issuer
  if (!options.validateIssuer) {
    log.warn(`We are not validating the issuer.
      This is fine if you are expecting multiple organizations to connect to your app.
      Otherwise you should validate the issuer.`);
  }

  // validate other necessary option items provided, we validate them here and only once
  var itemsToValidate = objectTransform({
    source: options,
    pick: ['clientID', 'callbackURL', 'responseType', 'responseMode', 'identityMetadata']
  });
  var validatorConfiguration = {
    clientID: Validator.isNonEmpty,
    callbackURL: Validator.isURL,   // allow http so developer can use http://localhost:3000
    responseType: Validator.isTypeLegal,
    responseMode: Validator.isModeLegal,
    identityMetadata: Validator.isHttpsURL
  };
  // validator will throw exception if a required option is missing
  var validator = new Validator(validatorConfiguration);
  validator.validate(itemsToValidate);

  // check if Azure v2.0 is being used, v2.0 doesn't have a userinfo endpoint
  if (options.identityMetadata.indexOf('/v2.0/') != -1)
    this._options.isV2 = true;
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function authenticateStrategy(req, options) {
  /* 
   * We should be careful using 'this'. Avoid the usage like `this.xxx = ...`
   * unless you know what you are doing.
   *
   * In the passport source code 
   * (https://github.com/jaredhanson/passport/blob/master/lib/middleware/authenticate.js)
   * when it attempts to call the `oidcstrategy.authenticate` function, passport
   * creates an instance inherting oidcstrategy and then calls `instance.authenticate`.  
   * Therefore, when we come here, `this` is the instance, its prototype is the
   * actual oidcstrategy, i.e. the `Strategy`. This means:
   * (1) `this._options = `, `this._verify = `, etc only adds new fields to the
   *      instance, it doesn't change the values in oidcstrategy, i.e. `Strategy`. 
   * (2) `this._options`, `this._verify`, etc returns the field in the instance,
   *     and if there is none, returns the field in oidcstrategy, i.e. `strategy`.
   * (3) each time we call `authenticate`, we will get a brand new instance
   * 
   * If you want to change the values in `Strategy`, use 
   *      const oidcstrategy = Object.getPrototypeOf(self);
   * to get the strategy first.
   *
   * Note: Simply do `const self = Object.getPrototypeOf(this)` and use `self`
   * won't work, since the `this` instance has a couple of functions like
   * success/fail/error... which `authenticate` will call. The following is the
   * structure of `this`:
   *
   *   this
   *   | --  success:  function(user, info)
   *   | --  fail:     function(challenge, status)
   *   | --  redirect: function(url, status)
   *   | --  pass:     function()
   *   | --  __proto__:  Strategy
   *                 | --  _verify
   *                 | --  _options
   *                 | --  ...
   *                 | --  __proto__:
   *                              | --  authenticate:  function(req, options)
   *                              | --  ...
   */ 
  const self = this;

  // Allow for some overrides that may come in to the authenticate strategy.
  //
  //       It's important all options are in self._options before we continue, as we'll be validating these and
  //       loading them through a validator. We should only use the data in configurator() for actual param passing
  //       otherwise we could have injection issues.
  //

  if (options.resourceURL) { self._options.resourceURL = options.resourceURL; }
  if (options.resourceType) { self._options.responseType = options.responseType; }
  if (options.responseMode) { self._options.responseMode = options.responseMode; }

  async.waterfall(
    [
      // compute metadata url
      (next) => {
        // B2C interception
        let metadataUrl = self._options.identityMetadata;

        // use 'ordinary' as the default cachekey, in the case of B2C, we will
        // change the value to policy later
        let cachekey = 'ordinary';

        // We listen for the p paramter in any response and set it. If it has been set already and in memory (profile) we skip this as it's not necessary to set again.
        // @TODO when forceB2C is set but no req.query.p is present, the policy variable would be 'undefined'
        if (req.query.p || options.forceB2C) {
          log.info('B2C: Found a policy inside of the login request. This is a B2C tenant!');

          if (!self._options.tenantName) {
            log.error(`For B2C you must specify a tenant name, none was presented to Strategy as required.
              (example: tenantName:contoso.onmicrosoft.com)`);
            return next(new TypeError(`OIDCStrategy requires you specify a tenant name to
              Strategy if using a B2C tenant. (example: tenantName:contoso.onmicrosoft.com')`));
          }

          // @TODO: could be undefined
          const policy = req.query.p;

          // @TODO: assumes that self._options.identityMetadata is of type string.
          //        according to Strategy constructor, it could also be a PEM encodede public key
          metadataUrl = self._options.identityMetadata
            .replace('common', self._options.tenantName)
            .concat(`?p=${policy}`);

          cachekey = 'policy: ' + policy; // this policy will become cache key.

          log.info('B2C: New Metadata url provided to Strategy was: ', metadataUrl);
        }

        self.metadata = new Metadata(metadataUrl, 'oidc', self._options);

        return next(null, metadataUrl, cachekey);
      },
      // load options from metadata url
      (metadataUrl, cachekey, next) => {
        self.setOptions(self._options, metadataUrl, cachekey, next);
      },
      // handle error response
      (next) => {
        var err = undefined;
        var err_description = undefined;

        if (req.query && req.query.error) {
          err = req.query.error;
          err_description = req.query.error_description;
        } else if (req.body && req.body.error) {
          err = req.body.error;
          err_description = req.body.error_description;
        } else {
          return next();
        }

        log.info('Error received in the response was: ', err);
        if (err_description)
          log.info('Error description received in the response was: ', err_description);

        // Unfortunately, we cannot return the 'error description' to the user, since 
        // it goes to http header by default and it usually contains characters that
        // http header doesn't like, which causes the program to crash. 
        return self.fail(err);
      },
      // handle authorize code response (incoming redirect after user consent was given)
      (next) => {
        if (!(
            (req.method === 'GET' && req.query && req.query.code) ||
            (req.method === 'POST' && req.body && req.body.code))) {
          return next();
        }

        // check state
        var stateCheckResult = stateHandler.verifyState(req, self._key);
        if (!stateCheckResult.valid) {
          return self.fail(stateCheckResult.errorMessage);
        }

        // get code
        const code = (req.query && req.query.code) ? req.query.code : req.body.code;
        if (!code) {
          return self.fail('Failed to extract authorization code from request object');
        }        
        log.info('OAUTH2: Got access code: ', code);

        // use `null` as identifier since we are in the callback phase of OAuth 2.0 Dance already
        // identifier only has impact on the `authorize` endpoint
        return self.configure(null, (err, config) => {
          if (err) {
            return next(err);
          }

          const oauth2 = new OAuth2(
            config.clientID, // consumerKey
            config.clientSecret, // consumer secret
            '', // baseURL (empty string because we use absolute urls for authorize and token paths)
            config.authorizationURL, // authorizePath
            config.tokenURL, // accessTokenPath
            {} // customHeaders
          );

          let callbackURL = config.callbackURL;
          // options.callbackURL is merged into config object while `setOptions` call
          if (!callbackURL) {
            return next(new Error('no callbackURL found'));
          }

          const parsedCallbackURL = url.parse(callbackURL);
          if (!parsedCallbackURL.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req), callbackURL);
          }

          return oauth2.getOAuthAccessToken(code, {
            grant_type: 'authorization_code',
            redirect_uri: callbackURL,
            }, (getOAuthAccessTokenError, accessToken, refreshToken, params) => {
            if (getOAuthAccessTokenError) {
              return next(new InternalOAuthError('failed to obtain access token', getOAuthAccessTokenError));
            }

            log.info('TOKENS RECEIVED: %j', {
              accessToken,
              refreshToken,
              params,
            });

            var id_token = params.id_token;

            return self._validateIdToken(id_token, req, (jwtClaimsStr, jwtClaims) => {
              // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
              // 'sub' claim was named 'user_id'.  Many providers still issue the
              // claim under the old field, so fallback to that.
              const sub = jwtClaims.sub || jwtClaims.user_id;
              const iss = jwtClaims.iss;

              return self._shouldLoadUserProfile(iss, sub, (shouldLoadUserProfileError, load) => {
                if (shouldLoadUserProfileError) {
                  return next(shouldLoadUserProfileError);
                }

                if (load && self._options.isV2) {
                  log.warn(`Azure v2.0 does not have a 'userinfo' endpoint, we will use the claims in id_token for the profile.`)
                } else if (load) {
                  let parsedUrl;
                  try {
                    parsedUrl = url.parse(config.userInfoURL, true);
                  } catch (urlParseException) {
                    return next(
                      new InternalOpenIDError(
                        `Failed to parse config property 'userInfoURL' with value ${config.userInfoURL}`,
                        urlParseException
                      )
                    );
                  }
                  parsedUrl.query.schema = 'openid';
                  delete parsedUrl.search; // delete operations are slow; should we rather just overwrite it with {}
                  const userInfoURL = url.format(parsedUrl);

                  // ask oauth2 to use authorization header to bearer access token
                  oauth2.useAuthorizationHeaderforGET(true);
                  return oauth2.get(userInfoURL, accessToken, (getUserInfoError, body) => {
                    if (getUserInfoError) {
                      return next(new InternalOAuthError('failed to fetch user profile', getUserInfoError));
                    }

                    log.info('PROFILE LOADED FROM MS IDENTITY', body);

                    // use try / catch around JSON.parse --> could fail unexpectedly
                    try {
                      return onProfileLoaded(self, {
                        req,
                        sub,
                        iss,
                        profile: makeProfileObject(JSON.parse(body), body),
                        jwtClaims,
                        accessToken,
                        refreshToken,
                        params,
                      });
                    } catch (ex) {
                      return next(ex);
                    }
                  });
                }

                // lets do an id_token fallback. We use id_token over userInfo endpoint for now
                return onProfileLoaded(self, {
                  req,
                  sub,
                  iss,
                  profile: makeProfileObject(jwtClaims, jwtClaimsStr),
                  jwtClaims,
                  accessToken,
                  refreshToken,
                  params,
                });
              });
            });
          });
        });
      },
      // handle the case where you receive the idToken, either in query or body
      (next) => {
        // see if we have id_token in body or query
        var id_token = undefined;
        if (req.body && req.body.id_token) {
          id_token = req.body.id_token;
        } else if (req.query && req.query.id_token) {
          id_token = req.query.id_token;
        } else {
          return next();
        }

        // log the id_token we got
        log.info('received id_token: ', id_token);

        // check state
        var stateCheckResult = stateHandler.verifyState(req, self._key);
        if (!stateCheckResult.valid) {
          return self.fail(stateCheckResult.errorMessage);
        }

        // validate the id_token, and use the validated id_token content in the callback
        return self._validateIdToken(id_token, req, (jwtClaimsStr, jwtClaims) => {
          // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
          // 'sub' claim was named 'user_id'.  Many providers still issue the
          // claim under the old field, so fallback to that.
          const sub = jwtClaims.sub || jwtClaims.user_id;
          const iss = jwtClaims.iss;

          return self._shouldLoadUserProfile(iss, sub, (err, load) => {
            if (err) {
              return next(err);
            }

            if (load) {
              // we do not have a userinfo endpoint for id token at the moment
              log.warn('We do not have a userinfo endpoint for id_token, we will use the claims in id_token for the profile.');
            }

            // we are not doing auth code so we set the tokens to null
            const accessToken = null;
            const refreshToken = null;
            const params = null;

            // lets do an id_token fallback. We use id_token over userInfo endpoint for now
            // log.info('PROFILE FALLBACK: Since we did not use the UserInfo endpoint, falling back to id_token for profile.');

            return onProfileLoaded(self, {
              req,
              sub,
              iss,
              profile: makeProfileObject(jwtClaims, jwtClaimsStr),
              jwtClaims,
              accessToken,
              refreshToken,
              params,
            });
          });
        });
      },
      // initialize OAuth 2.0 Authorize Flow
      (next) => {
        // The request being authenticated is initiating OpenID Connect
        // authentication. Prior to redirecting to the provider, configuration will
        // be loaded. The configuration is typically either pre-configured or
        // discovered dynamically. When using dynamic discovery, a user supplies
        // their identifer as input.

        log.info(`OPENID CONNECT: We are in the OpenID Connect Inital Flow.
          Assumed because no auth code was in the query and we are not POST.`);
        log.info('Body received was: ', req.body);

        let identifier;
        if (req.body && req.body[this._identifierField]) {
          identifier = req.body[this._identifierField];
        } else if (req.query && req.query[this._identifierField]) {
          identifier = req.query[this._identifierField];
        }

        return self.configure(identifier, (configureError, config) => {
          if (configureError) {
            return next(configureError);
          }

          let callbackURL = options.callbackURL || config.callbackURL;
          if (callbackURL) {
            const parsed = url.parse(callbackURL);
            if (!parsed.protocol) {
              // The callback URL is relative, resolve a fully qualified URL from the
              // URL of the originating request.
              callbackURL = url.resolve(utils.originalURL(req), callbackURL);
            }
          }

          log.info('Going in with our config loaded as: ', config);

          const params = {};
          if (self.authorizationParams) {
            _.assign(params, self.authorizationParams(options));
          }
          _.assign(params, {
            redirect_uri: callbackURL,
          }, objectTransform({
            source: config,
            map: {
              responseMode: 'response_mode',
              responseType: 'response_type',
              clientID: 'client_id',
              resourceURL: 'resource',
            },
          }));

          log.info('We are sending the response_type: ', params.response_type);
          log.info('We are sending the response_mode: ', params.response_mode);

          let scope = config.scope;
          if (Array.isArray(scope)) {
            scope = scope.join(config.scopeSeparator);
          }
          if (scope) {
            params.scope = ['openid', scope].join(config.scopeSeparator);
          } else {
            params.scope = 'openid';
          }

          // if (policy) { params['p'] = policy; }; // Policy parameter should be included.

          // add state to params and session, use the given one or generate one
          let state = params.state = options.state || utils.uid(24);
          stateHandler.addStateToSession(req, self._key, state);

          // add nonce, use a randomly generated one
          let nonce = params.nonce = utils.uid(16);
          nonceHandler.addNonceToSession(req, self._key, nonce);

          let location;

          // Implement support for standard OpenID Connect params (display, prompt, etc.)

          if (req.query.p) {
            location = `${config.authorizationURL}&${querystring.stringify(params)}`;
          } else {
            location = `${config.authorizationURL}?${querystring.stringify(params)}`;
          }

          return self.redirect(location);
        });
      },
    ],
    (waterfallError) => { // This function gets called after the three tasks have called their 'task callbacks'
      if (waterfallError) {
        return self.error(waterfallError);
      }
      return true;
    });
};

/**
 * Load options from metadata to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object} options
 */
Strategy.prototype.setOptions = function setOptions(options, metadataUrl, cachekey, done) {
  const self = this;

  // Loading metadata from endpoint.
  async.waterfall([
    // fetch the metadata
    function loadMetadata(next) {
      log.info('Parsing Metadata: ', metadataUrl);

      memoryCache.wrap(cachekey, (cacheCallback) => {
        //self.metadata = new Metadata(metadataUrl, 'oidc', options);
        self.metadata.fetch((fetchMetadataError) => {
          if (fetchMetadataError) {
            return cacheCallback(new Error(`Unable to fetch metadata: ${fetchMetadataError}`));
          }
          return cacheCallback(null, self.metadata);
        });
      }, { ttl }, next);
    },
    // merge fetched metadata with options
    function loadOptions(metadata, next) {
      self.metadata = metadata;

      // fetched metadata always takes precendence over configured options

      // use default values where no option is present
      const opts = {
        identifierField: 'openid_identifier', // What's the recommended field name for OpenID Connect?
        scopeSeparator: ' ',
        tokenInfoURL: null,
      };

      const pickedFromOptions = objectTransform({
        source: options,
        pick: [
          'callbackURL',
          'clientID',
          'clientSecret',
          'identifierField',
          'passReqToCallback',
          'resourceURL',
          'responseMode',
          'responseType',
          'scope',
          'scopeSeparator',
        ],
      });

      // pick values from fetched metadata
      const pickedFromMetadata = objectTransform({
        source: metadata.oidc,
        map: {
          auth_endpoint: 'authorizationURL',
          end_session_endpoint: 'revocationURL',
          issuer: 'oidcIssuer',
          token_endpoint: 'tokenURL',
          tokeninfo_endpoint: 'tokenInfoURL',
          userinfo_endpoint: 'userInfoURL',
        },
      });

      _.assign(opts, pickedFromOptions, pickedFromMetadata);

      // Now that we have our options for configuration, let's check them for issues.
      const validatorConfig = {
        authorizationURL: Validator.isHttpsURL,
        tokenURL: Validator.isHttpsURL,
      };

      // validator will throw exception if a required option is missing
      const checker = new Validator(validatorConfig);
      checker.validate(opts);

      next(null, opts);
    },
    // push merged options to self._configurers for later use
    function setConfiguration(opts, next) {
      log.info('Setting configuration for later', opts);

      self.configure((identifier, configureDone) => {
        return configureDone(null, objectTransform({
          source: opts,
          pick: [
            'authorizationURL',
            'callbackURL',
            'clientID',
            'clientSecret',
            'identifierField',
            'oidcIssuer',
            'passReqToCallback',
            'resourceURL',
            'responseMode',
            'responseType',
            'revocationURL',
            'scope',
            'scopeSeparator',
            'tokenInfoURL',
            'tokenURL',
            'userInfoURL',
          ],
        }));
      });
      next();
    },
  ], done);
};

/**
 * Register a function used to configure the strategy.
 *
 * OpenID Connect is an identity layer on top of OAuth 2.0.  OAuth 2.0 requires
 * knowledge of certain endpoints (authorization, token, etc.) as well as a
 * client identifier (and corresponding secret) registered at the authorization
 * server.
 *
 * Configuration functions are responsible for loading this information.  This
 * is typically done via one of two popular mechanisms:
 *
 *   - The configuration is known ahead of time, and pre-configured via options
 *     to the strategy.
 *   - The configuration is dynamically loaded, using optional discovery and
 *     registration specifications.  (Note: Providers are not required to
 *     implement support for dynamic discovery and registration.  As such, there
 *     is no guarantee that this will result in successfully initiating OpenID
 *     Connect authentication.)
 *
 * @param {Function} fn
 * @api public
 */
Strategy.prototype.configure = function configureStrategy(identifier, done) {
  if (typeof identifier === 'function') {
    return this._configurers.push(identifier);
  }

  // private implementation that traverses the chain of configurers, attempting
  // to load configuration
  const stack = this._configurers;
  (function pass(i, err, config) {
    // an error or configuration was obtained, done
    if (err || config) {
      return done(err, config);
    }

    const layer = stack[i];
    if (!layer) {
      // Strategy-specific functions did not result in obtaining configuration
      // details.  Proceed to protocol-defined mechanisms in an attempt
      // to discover the provider's configuration.
      return setup(identifier, done);
    }

    try {
      layer(identifier, (layerError, layerConfig) => { pass(i + 1, layerError, layerConfig); });
    } catch (ex) {
      return done(ex);
    }
    return false;
  }(0));
  return false;
};

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function shouldLoadUserProfile(issuer, subject, done) {
  // check if _skipUserProfile is an async function (expexts more than 2 arguments)
  if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 2) {
    return this._skipUserProfile(issuer, subject, (err, skip) => {
      return done(err, !skip);
    });
  }
  const skip = (typeof this._skipUserProfile === 'function') ?
    this._skipUserProfile(issuer, subject) :
    this._skipUserProfile;
  return done(null, !skip);
};

/**
 * validate idToken, and pass the validated claims and the payload to callback
 *
 * @param {String} idToken
 * @param {Object} req
 * @param {Function} callback
 */
Strategy.prototype._validateIdToken = function validateIdToken(idToken, req, callback) {
  const self = this;

  if (!idToken)
    return self.fail('ID Token not present in response');

  // decode IdToken
  const decoded = jws.decode(idToken);
  if (decoded == null)
    return self. fail(null, false, 'Invalid JWT token');
  log.info('token decoded: ', decoded);

  // get Pem Key
  var PEMkey = undefined;
  if (decoded.header.x5t) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.x5t);
  } else if (decoded.header.kid) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.kid);
  } else {
    return self.fail('We did not reveive a token we know how to validate');
  }

  var options = self._options;
  // since the id_token is for itself, so the id_token is the clientID by default
  if (!options.audience) {
    options.audience = options.clientID;
  }

  // verify IdToken signature and claims
  return jwt.verify(idToken, PEMkey, options, (err, jwtClaims) => {
    if (err)
      return self.fail("cannot verify id token");
    log.info("Claims received: ", jwtClaims);

    // check the nonce in claims
    var nonceCheckResult = nonceHandler.verifyNonce(req, self._key, jwtClaims.nonce);
    if (!nonceCheckResult.valid)
      return self.fail(nonceCheckResult.errorMessage);

    // return jwt claims and jwt claims string
    var idTokenSegments = idToken.split('.');
    var jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
    return callback(jwtClaimsStr, jwtClaims);
  });
};

module.exports = Strategy;
