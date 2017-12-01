
/**
 * Module dependencies.
 */

const KoaOAuthServer = require('../../');
const Request = require('oauth2-server').Request;
const Response = require('oauth2-server').Response;
const koa = require('koa');
const request = require('supertest');
const sinon = require('sinon');

/**
 * Test `KoaOAuthServer`.
 */

describe('KoaOAuthServer', function() {
  let app;

  beforeEach(function() {
    app = new koa();
  });

  describe('authenticate()', function() {
    it('should call `authenticate()`', async function () {
      let oauth = new KoaOAuthServer({ model: {} });

      sinon.stub(oauth.server, 'authenticate').returns({});

      app.use(oauth.authenticate());

      await request(app.callback())
        .get('/', function () {
          oauth.server.authenticate.callCount.should.equal(1);
          oauth.server.authenticate.firstCall.args.should.have.length(2);
          oauth.server.authenticate.firstCall.args[0].should.be.an.instanceOf(Request);
          oauth.server.authenticate.firstCall.args[1].should.be.an.instanceOf(Response);
          oauth.server.authenticate.restore();
        });
    });
  });

  describe('authorize()', function() {
    it('should call `authorize()`', async function () {
      let oauth = new KoaOAuthServer({ model: {} });

      sinon.stub(oauth.server, 'authorize').returns({});

      app.use(oauth.authorize());

      await request(app.callback())
        .get('/', function (){
          oauth.server.authorize.callCount.should.equal(1);
          oauth.server.authorize.firstCall.args.should.have.length(2);
          oauth.server.authorize.firstCall.args[0].should.be.an.instanceOf(Request);
          oauth.server.authorize.firstCall.args[1].should.be.an.instanceOf(Response);
          oauth.server.authorize.restore();
        });
    });
  });

  describe('token()', function() {
    it('should call `token()`', async function () {
      let oauth = new KoaOAuthServer({ model: {} });

      sinon.stub(oauth.server, 'token').returns({});

      app.use(oauth.token());

      await request(app.callback())
        .get('/', function () {
          oauth.server.token.callCount.should.equal(1);
          oauth.server.token.firstCall.args.should.have.length(2);
          oauth.server.token.firstCall.args[0].should.be.an.instanceOf(Request);
          oauth.server.token.firstCall.args[1].should.be.an.instanceOf(Response);
          oauth.server.token.restore();
        });
    });
  });
});
