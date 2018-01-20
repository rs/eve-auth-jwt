from eve_auth_jwt import requires_token
from eve_auth_jwt.auth import JWTAuth


def register(app):
    @app.route('/token/success')
    @requires_token(audiences=['aud1'], allowed_roles=['super'])
    def requires_token_success():
        return 'true'

    @app.route('/token/failure')
    @requires_token(audiences=['aud1'], allowed_roles=['super'])
    def requires_token_failure():
        return 'should not authenticate'

    custom_auth = JWTAuth('custom_secret')
    custom_auth.issuer = 'custom_issuer'

    @app.route('/custom/success')
    @custom_auth.requires_token(audiences=['aud1'], allowed_roles=['super'])
    def requires_token_success2():
        return 'true'
