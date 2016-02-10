from flask import abort
from eve_auth_jwt import requires_token


def register(app):
    @app.route('/token/success')
    @requires_token(audiences=['aud1'], allowed_roles=['super'])
    def requires_token_success():
        return 'true'

    @app.route('/token/failure')
    @requires_token(audiences=['aud1'], allowed_roles=['super'])
    def requires_token_failure():
        abort(422)
