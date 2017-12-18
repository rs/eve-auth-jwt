# -*- coding: utf-8 -*-

import unittest
import jwt
from eve import Eve
from eve_auth_jwt import JWTAuth
from flask import g
from eve_auth_jwt.tests import test_routes

settings = {
    'JWT_SECRET': 'secret',
    'JWT_ISSUER': 'https://domain.com/token',
    'JWT_AUDIENCES': ['aud1'],
    'JWT_ROLES_CLAIM': 'roles',
    'JWT_SCOPE_CLAIM': 'scope',
    'DOMAIN': {
        'foo': {
            'schema': {
                'name': {},
            },
            'resource_methods': ['POST', 'GET'],
        },
        'bar': {
            'audiences': ['aud2'],
        },
        'baz': {
            'allowed_roles': ['role1', 'role2'],
        },
    },
}


class TestBase(unittest.TestCase):
    def setUp(self):
        self.app = Eve(settings=settings, auth=JWTAuth)
        test_routes.register(self.app)

        self.test_client = self.app.test_client()

    def test_restricted_access(self):
        r = self.test_client.get('/foo')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers['WWW-Authenticate'], 'Bearer realm="eve_auth_jwt"')

    def test_token_error(self):
        r = self.test_client.get('/foo?access_token=invalid')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers['WWW-Authenticate'], 'Bearer realm="eve_auth_jwt", error="invalid_token"')

    def test_valid_token_header(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        auth = [('Authorization', 'Bearer {}'.format(token.decode('utf-8')))]
        r = self.test_client.get('/foo', headers=auth)
        self.assertEqual(r.status_code, 200)

    def test_valid_token_query(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 200)

    def test_token_claims_context(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        with self.app.test_client() as client:
            client.get('/foo?access_token={}'.format(token.decode('utf-8')))
            self.assertEqual(g.get('authen_claims'), claims)

    def test_invalid_token_secret(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'invalid secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_missing_token_subject(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_invalid_token_issuer(self):
        claims = {'iss': 'https://invalid-domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_invalid_token_audience(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud2',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_valid_token_resource_audience(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud2',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/bar?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 200)

    def test_invalid_token_resource_audience(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/bar?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_valid_token_role(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'roles': ['role1']}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/baz?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 200)

    def test_invalid_token_role(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/baz?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_token_role_context(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'roles': ['role1']}
        token = jwt.encode(claims, 'secret')
        with self.app.test_client() as client:
            client.get('/baz?access_token={}'.format(token.decode('utf-8')))
            self.assertEqual(g.get('authen_roles'), ['role1'])

    def test_token_role_context_always(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'roles': ['role1']}
        token = jwt.encode(claims, 'secret')
        with self.app.test_client() as client:
            client.get('/foo?access_token={}'.format(token.decode('utf-8')))
            self.assertEqual(g.get('authen_roles'), ['role1'])

    def test_token_scope(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'scope': 'user'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 200)

    def test_token_scope_viewer_read(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'scope': 'viewer'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 200)

    def test_token_scope_viewer_write(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'scope': 'viewer'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.post('/foo?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401)

    def test_requires_token_success(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'roles': ['super'],
                  'scope': 'user'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/token/success?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 200, r.data)

    def test_requires_token_failure_audience(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud2',
                  'sub': '0123456789abcdef01234567',
                  'roles': ['super'],
                  'scope': 'user'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/token/failure?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401, r.data)

    def test_requires_token_failure_roles(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'roles': [],
                  'scope': 'user'}
        token = jwt.encode(claims, 'secret')
        r = self.test_client.get('/token/failure?access_token={}'.format(token.decode('utf-8')))
        self.assertEqual(r.status_code, 401, r.data)

    def test_auth_header_token_success(self):
        claims = {'iss': 'https://domain.com/token',
                  'aud': 'aud1',
                  'sub': '0123456789abcdef01234567',
                  'roles': ['super'],
                  'scope': 'user'}
        token = jwt.encode(claims, 'secret')
        headers = {'Authorization': 'Bearer {}'.format(token.decode('utf-8'))}
        r = self.test_client.get('/token/success', headers=headers)
        self.assertEqual(r.status_code, 200)

    def test_auth_header_token_failure(self):
        r = self.test_client.get('/token/failure')
        self.assertEqual(r.status_code, 401, r.data)


if __name__ == '__main__':
    unittest.main()
