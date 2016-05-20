Eve Auth JWT
============

.. image:: https://img.shields.io/pypi/v/eve-auth-jwt.svg
    :target: https://pypi.python.org/pypi/eve-auth-jwt

.. image:: https://travis-ci.org/rs/eve-auth-jwt.svg?branch=master
    :target: https://travis-ci.org/rs/eve-auth-jwt

An OAuth 2 JWT token validation module for `Eve <http://python-eve.org>`_.

Installation
------------

To install eve-auth-jwt, simply:

    $ pip install eve-auth-jwt

At Eve initialization::

    from eve import Eve
    from eve_auth_jwt import JWTAuth

    app = Eve(auth=JWTAuth, settings=SETTINGS)

Configuration
-------------

This module reads its configuration form Eve settings. Here is the list of new directives:

* ``JWT_SECRET`` (required): Defines the symetric secret token secret used to de/encode the token (async keys support is a TODO).
* ``JWT_ISSUER`` (required): Defines the required token issuer (``iss`` claim).
* ``JWT_AUDIENCES``: Defines a list of accepted audiences (``aud`` claim). If not provided, only tokens with no audience set will be accepted. The resource level ``audiences`` parameter is also available.
* ``JWT_ROLES_CLAIM``: Defines the claim name for roles. If set, Eve roles check will be activated, and any resources with ``allowed_roles`` set will require to have those roles present in the defined token's claim.
* ``JWT_SCOPE_CLAIM``: Defines the claim name for scope. If set and the token has a claim of the same name containing the string ``viewer``, only ``GET`` and ``HEAD`` methods will be granted. All other values are ignored and added to the list of exposed roles with the ``scope:`` prefix.

Reading Roles
-------------

If access is granted, the authentication module exposes roles and token's claims thru ``get_authen_roles()`` and ``get_authen_claims()`` methods. You may access those values from your event hook as follow::

    def my_hook(...)
        resource_def = app.config['DOMAIN'][resource_name]
        auth = resource_def['authentication']
        if 'somerole' in auth.get_authen_roles():
            # grant some finer access


Securing custom routes
----------------------

JWT Authorization can be applied to any custom routes using the `@requires_token` wrapper. This annotation will only provide *audience and role access control*. User level access must be written manually.

Example of audience access control::

    from eve_auth_jwt import requires_token, get_request_auth_value

    @app.route('/my_resource/download', methods=['GET'])
    @requires_token(audiences=['myAudience'])
    def csv_download():
        # Allows all users with myAudience to access download
        account_id = get_request_auth_value()
        if check_user(account_id):

            abort(401)

        return generateCSV(account_id)

Example of `myAdmin` access control::

    from eve_auth_jwt import requires_token

    @app.route('/admin/my_resource/download', methods=['GET'])
    @requires_token(audiences=['myAudience'], allowed_roles=['myAdmin'])
    def csv_download():
        account_id = request.args.get('account_id', None)
        return generateCSV(account_id)


Access the parsed JWT token values
----------------------------------

The parsed JWT token values are stored in the `flask.g` dict, but custom functions exist to aid in reading the values. The values are only available after the JWT token integrity check and user authorization occurs.

Example of access the parse JWT token fields::

    from eve_auth_jwt import get_request_auth_value, get_authen_claims, get_authen_roles

    def my_fn():
        # Request authentication value as a str
        account_id = get_request_auth_value()

        # JWT claims as a dict[str]
        payload = get_authen_claims()

        # Roles as arr[str]
        roles = get_authen_roles()


Licenses
--------

All source code is licensed under the `MIT License <https://raw.githubusercontent.com/rs/eve-auth-jwt/master/LICENSE>`_.
