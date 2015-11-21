# -*- coding: utf-8 -*-

from eve.auth import BasicAuth
from eve.utils import config
from flask import request, Response, g
from flask import abort
import jwt


class JWTAuth(BasicAuth):
    """
    Implements JWT token validation support.
    """
    def set_authen_claims(self, claims):
        g.authen_claims = claims

    def get_authen_claims(self):
        return g.get('authen_claims', {})

    def set_authen_roles(self, roles):
        g.authen_roles = roles

    def get_authen_roles(self):
        return g.get('authen_roles', [])

    def authorized(self, allowed_roles, resource, method):
        authorized = False

        if request.authorization:
            auth = request.authorization
            authorized = self.check_auth(auth.username, auth.password,
                                         allowed_roles, resource, method)
        elif request.args.get('access_token'):
            access_token = request.args.get('access_token')
            authorized = self.check_token(access_token, allowed_roles, resource, method)
        else:
            try:
                access_token = request.headers.get('Authorization').split(' ')[1]
                authorized = self.check_token(access_token, allowed_roles, resource, method)
            except:
                pass

        return authorized

    def authenticate(self):
        """
        Indicate to the client that it needs to authenticate via a 401.
        """
        if request.headers.get('Authorization') or request.args.get('access_token'):
            realm = 'Bearer realm="%s", error="invalid_token"' % __package__
        else:
            realm = 'Bearer realm="%s"' % __package__
        resp = Response(None, 401, {'WWW-Authenticate': realm})
        abort(401, description='Please provide proper credentials', response=resp)

    def check_token(self, token, allowed_roles, resource, method):
        """
        This function is called when a token is sent throught the access_token
        parameter or the Authorization header as specified in the oAuth 2 specification.

        The provided token is validated with the JWT_SECRET defined in the Eve configuration.
        The token issuer (iss claim) must be the one specified by JWT_ISSUER and the audience
        (aud claim) must be one of the value(s) defined by the either the "audiences" resource
        parameter or the global JWT_AUDIENCES configuration.

        If JWT_ROLES_CLAIM is defined and a claim by that name is present in the token, roles
        are checked using this claim.

        If a JWT_SCOPE_CLAIM is defined and a claim by that name is present in the token, the
        claim value is check, and if "viewer" is present, only GET and HEAD methods will be
        allowed. The scope name is then added to the list of roles with the scope: prefix.

        If the validation succeed, the claims are stored and accessible thru the
        get_authen_claims() method.
        """
        resource_conf = config.DOMAIN[resource]
        audiences = resource_conf.get('audiences', config.JWT_AUDIENCES)
        if audiences is None:
            # Check for a token with no audience
            audiences = [None]

        # Try to decode token with each allowed audience
        for audience in audiences:
            try:
                payload = jwt.decode(token, key=config.JWT_SECRET, issuer=config.JWT_ISSUER, audience=audience)
                break  # this skips the for/else clause
            except jwt.InvalidAudienceError:
                continue
            except Exception:
                return False
        else:
            return False

        # Get account id
        account_id = payload.get('sub')
        if account_id is None:
            return False

        roles = None

        # Check scope is configured and add append it to the roles
        if config.JWT_SCOPE_CLAIM and payload.get(config.JWT_SCOPE_CLAIM):
            scope = payload.get(config.JWT_SCOPE_CLAIM)
            # Viewers can only read
            if scope == 'viewer' and method not in ['GET', 'HEAD']:
                return False
            roles = ['scope:%s' % scope]

        # If roles claim is defined, gather roles from the token
        if config.JWT_ROLES_CLAIM:
            roles = payload.get(config.JWT_ROLES_CLAIM, []) + (roles or [])

        # Check roles if scope or role claim is set
        if allowed_roles and roles is not None:
            if not any(role in roles for role in allowed_roles):
                return False

        # Save roles for later access
        self.set_authen_roles(roles)

        # Save claims for later access
        self.set_authen_claims(payload)

        # Limit access to the authen account
        self.set_request_auth_value(account_id)

        return True
