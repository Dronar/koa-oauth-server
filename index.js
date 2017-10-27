
/**
 * Module dependencies.
 */

var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var NodeOAuthServer = require('oauth2-server');
var Request = require('oauth2-server').Request;
var Response = require('oauth2-server').Response;
var UnauthorizedRequestError = require('oauth2-server/lib/errors/unauthorized-request-error');
var co = require('co');

/**
 * Constructor.
 */

function KoaOAuthServer(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  for (var fn in options.model) {
    options.model[fn] = co.wrap(options.model[fn]);
  }

  this.server = new NodeOAuthServer(options);
}

/**
 * Authentication Middleware.
 *
 * Returns a middleware that will validate a token.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-7)
 */

KoaOAuthServer.prototype.authenticate = function() {
  var server = this.server;

  return async function (ctx, next) {
    var request = new Request(ctx.request);
    var response = new Response(ctx.response);

    try {
      var token = await server.authenticate(request, response);
      ctx.state.oauth = {
        token: token
      };
    } catch (e) {
      return handleError.call(ctx, e);
    }

    return next();
  };
};

/**
 * Authorization Middleware.
 *
 * Returns a middleware that will authorize a client to request tokens.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
 */

KoaOAuthServer.prototype.authorize = function() {
  var server = this.server;

  return async function (ctx, next) {
    var request = new Request(ctx.request);
    var response = new Response(ctx.response);

    try {
      var code = await server.authorize(request, response);
      ctx.state.oauth = {
        code: code
      };

    } catch (e) {
      return handleError.call(ctx, e);
    }

    return next();
  };
};

/**
 * Grant Middleware
 *
 * Returns middleware that will grant tokens to valid requests.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
 */

KoaOAuthServer.prototype.token = function() {
  var server = this.server;

  return async function (ctx, next) {
    var request = new Request(ctx.request);
    var response = new Response(ctx.response);

    try {
      var token = await server.token(request, response);
      ctx.state.oauth = {
        token: token
      };

    } catch (e) {
      return handleError.call(this, e);
    }

    return next();
  };
};


/**
 * Handle error.
 */

var handleError = function(e) {

  if (e instanceof UnauthorizedRequestError) {
    this.status = e.code;
  } else {
    this.body = { error: e.name, error_description: e.message };
    this.status = e.code;
  }

  return this.app.emit('error', e, this);
};

/**
 * Export constructor.
 */

module.exports = KoaOAuthServer;
