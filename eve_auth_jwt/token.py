from eve.utils import config
from flask import request
import jwt


def verify_token(token, method=None, audiences=[], allowed_roles=[]):
    # Try to decode token with each allowed audience
    for audience in audiences:
        try:
            payload = jwt.decode(token, key=config.JWT_SECRET, issuer=config.JWT_ISSUER, audience=audience)
            break  # this skips the for/else clause
        except jwt.InvalidAudienceError:
            continue
        except Exception:
            return (False, None, None, None)
    else:
        return (False, None, None, None)

    # Get account id
    account_id = payload.get('sub')
    if account_id is None:
        return (False, payload, None, None)

    roles = None

    # Check scope is configured and add append it to the roles
    if config.JWT_SCOPE_CLAIM and payload.get(config.JWT_SCOPE_CLAIM):
        scope = payload.get(config.JWT_SCOPE_CLAIM)
        # Viewers can only read
        if scope == 'viewer' and method not in ['GET', 'HEAD']:
            return (False, payload, account_id, None)
        roles = ['scope:%s' % scope]

    # If roles claim is defined, gather roles from the token
    if config.JWT_ROLES_CLAIM:
        roles = payload.get(config.JWT_ROLES_CLAIM, []) + (roles or [])

    # Check roles if scope or role claim is set
    if allowed_roles and roles is not None:
        if not any(role in roles for role in allowed_roles):
            return (False, payload, account_id, roles)

    return (True, payload, account_id, roles)


def extract_token():
    """
    Parse access token from incoming request.

    Returns: (access_token, isParam)
        access_token (string or None): Access token
        isParam (boolean): Whether token was parsed from URL parameters or from the request header
    """
    if request.args.get('access_token'):
        return (request.args.get('access_token'), True)

    try:
        access_token = request.headers.get('Authorization').split(' ')[1]
        if access_token:
            return (access_token, False)
    except:
        pass
    return (None, False)
