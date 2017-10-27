
/**
 * Module dependencies.
 */

const InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
const NodeOAuthServer = require('oauth2-server');
const Request = require('oauth2-server').Request;
const Response = require('oauth2-server').Response;
const UnauthorizedRequestError = require('oauth2-server/lib/errors/unauthorized-request-error');
const co = require('co');

/**
 * Constructor.
 */

function KoaOAuthServer(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  for (let fn in options.model) {
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
  const server = this.server;

  return async function (ctx, next) {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);

    try {
      const token = await server.authenticate(request, response);
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
  const server = this.server;

  return async function (ctx, next) {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);

    try {
      const code = await server.authorize(request, response);
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
  const server = this.server;

  return async function (ctx, next) {
    const request = new Request(ctx.request);
    const response = new Response(ctx.response);

    try {
      const token = await server.token(request, response);
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
