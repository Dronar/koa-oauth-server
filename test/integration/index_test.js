
/**
 * Module dependencies.
 */

var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var KoaOAuthServer = require('../../');
var NodeOAuthServer = require('oauth2-server');
var bodyparser = require('koa-bodyparser');
var koa = require('koa');
var request = require('supertest');
var should = require('should');

/**
 * Test `KoaOAuthServer`.
 */

describe('KoaOAuthServer', function() {
  var app;

  beforeEach(function() {
    app = new koa();

    app.use(bodyparser());
    app.on('error', function() {});
  });

  describe('constructor()', function() {
    it('should throw an error if `model` is missing', function() {
      try {
        new KoaOAuthServer({});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should wrap generator functions in the model', function() {
      var model = {
        getAccessToken: function () {
          return 'foobar';
        }
      };

      new KoaOAuthServer({ model: model });

      model.getAccessToken().should.be.an.instanceOf(Promise);

      return model.getAccessToken()
        .then(function(data) {
          data.should.equal('foobar');
        })
        .catch(should.fail);
    });

    it('should set the `server`', function() {
      var oauth = new KoaOAuthServer({ model: {} });

      oauth.server.should.be.an.instanceOf(NodeOAuthServer);
    });
  });

  describe('authenticate()', function() {
    it('should return an error if `model` is empty', async function () {
      var oauth = new KoaOAuthServer({ model: {} });

      app.use(oauth.authenticate());

      await request(app.callback())
        .get('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getAccessToken()`' });
    });
  });

  describe('authorize()', function() {
    it('should return an error if response_type is missing', async function () {
      var model = {
        getAccessToken: function() {
          return { user: {} };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return {};
        }
      };
      var oauth = new KoaOAuthServer({ model: model });

      app.use(oauth.authorize());

      await request(app.callback())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send({ client_id: 12345})
        .expect({ error: 'invalid_request', error_description: 'Missing parameter: `response_type`' });
    });

    it('should return a `location` header with the code', async function() {
      var model = {
        getAccessToken: function() {
          return { user: {}};
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return { authorizationCode: 123 };
        }
      };
      var oauth = new KoaOAuthServer({ model: model });

      app.use(oauth.authorize());

      await request(app.callback())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send({ client_id: 12345, response_type: 'code' })
        .expect(302)
    });

    it('should return an error if `model` is empty', async function () {
      var oauth = new KoaOAuthServer({ model: {} });

      app.use(oauth.authorize());      

      await request(app.callback())
        .post('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' });
    });

    it('should emit an error if `model` is empty', async function () {
      var oauth = new KoaOAuthServer({ model: {} });

      app.use(oauth.authorize());

      await request(app.callback())
        .get('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' });
    });
  });

  describe('token()', function() {
    it('should return an `access_token`', async function () {
      var model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return { accessToken: 'foobar', client: {}, user: {} };
        }
      };
      var oauth = new KoaOAuthServer({ model: model });

      app.use(oauth.token());

      await request(app.callback())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', token_type: 'bearer' });
    });

    it('should return a `refresh_token`', async function () {
      var model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return { accessToken: 'foobar', client: {}, refreshToken: 'foobiz', user: {} };
        }
      };
      var oauth = new KoaOAuthServer({ model: model });

      app.use(oauth.token());

      await request(app.callback())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', refresh_token: 'foobiz', token_type: 'bearer' });
    });

    it('should return an error if `model` is empty', async function () {
      var oauth = new KoaOAuthServer({ model: {} });

      app.use(oauth.token());

      await request(app.callback())
        .post('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' });
    });
  });
});
