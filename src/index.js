const authentication = require('./internal/code-gen/authentication-api');
const DefaultOAuth2AccessToken = require('./internal/code-gen/authentication-api/model/DefaultOAuth2AccessToken');

class AuthenticationApi {

    /**
     * Create a new AuthenticationApi object.
     * @param {String} apiKey The API key used to access the provisioning api.
     * @param {String} baseUrl The URL of the auth service.
     * @param {Boolean} isLogsEnabled If true, the AuthenticationApi object logs its activity with console.log.
     */
    constructor(apiKey, baseUrl, isLogsEnabled) {
        this.client = new authentication.ApiClient();
        this.client.basePath = `${baseUrl}/auth/v3`;
        this.client.defaultHeaders = {'x-api-key': apiKey};
        this.authApi = new authentication.AuthenticationApi(this.client);
        if (isLogsEnabled) {
            this._loggerFunction = (msg) => {
                console.log(msg);
            };
        } else {
            this._loggerFunction = (msg) => {
            };
        }
    }

    _log(msg) {
        this._loggerFunction(msg);
    }

    /**
     * Build form parameters to retrieve token
     * @param {String} redirectUri  Uri to redirect
     * @param {String} code See [Authorization code](https://tools.ietf.org/html/rfc6749#section-1.3.1) for details
     * @param {Object} opts Optional parameters
     * @param {String} opts.clientId Use to identify PUBLIC clients without password
     * @return {Object.<String, Object>} form A map of form parameters and their values
     */
    static createFormAuthCodeGrantType(redirectUri, code, opts = {}) {
        if (redirectUri === undefined || redirectUri === null) {
            throw new Error("Missing the required parameter 'redirectUri' when calling createFormAuthCodeGrantType");
        }
        if (code === undefined || code === null) {
            throw new Error("Missing the required parameter 'code' when calling createFormAuthCodeGrantType");
        }
        return {
            'grant_type': 'authorization_code',
            'redirect_uri': redirectUri,
            'code': code,
            'client_id': opts['clientId']
        };
    }

    /**
     * Build form parameters to retrieve token
     * @param {String} username The agent&#39;s username, formatted as &#39;tenant\\username&#39;.
     * @param {String} password The agent&#39;s password.
     * @param {Object} opts Optional parameters
     * @param {String} opts.clientId Use to identify PUBLIC clients without password
     * @param {String} opts.scope The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value.
     * @return {Object.<String, Object>} form A map of form parameters and their values.
     */
    static createFormPasswordGrantType(username, password, opts = {}) {
        if (username === undefined || username === null) {
            throw new Error("Missing the required parameter 'username' when calling createFormPasswordGrantType");
        }
        if (password === undefined || password === null) {
            throw new Error("Missing the required parameter 'password' when calling createFormPasswordGrantType");
        }
        return {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': opts['clientId'],
            'scope': opts['scope']
        };
    }

    /**
     * Build form parameters to retrieve token
     * @param {String} refreshToken See [Refresh Token](https://tools.ietf.org/html/rfc6749#section-1.5) for details.
     * @param {Object} opts Optional parameters
     * @param {String} opts.clientId Use to identify PUBLIC clients without password
     * @param {String} opts.scope The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value.
     * @return {Object.<String, Object>} form A map of form parameters and their values.
     */
    static createFormParamRefreshTokenGrantType(refreshToken, opts = {}) {
        if (refreshToken === undefined || refreshToken === null) {
            throw new Error("Missing the required parameter 'username' when calling createFormPasswordGrantType");
        }
        return {
            'grant_type': 'refresh_token',
            'refresh_token': refreshToken,
            'client_id': opts['clientId'],
            'scope': opts['scope'],
        }
    }

    /**
     * Build form parameters to retrieve token
     * @param {Object} opts Optional parameters
     * @param {String} opts.scope The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value.
     * @return {Object.<String, Object>} form A map of form parameters and their values.
     */
    static createFormClientCredentialsGrantType(opts = {}) {
        return {
            'grant_type': 'client_credentials',
            'scope': opts['scope']
        }
    }

    /**
     * Retrieve access token
     * Retrieve an access token based on the grant type &amp;mdash; For more information, see [Token Endpoint](https://tools.ietf.org/html/rfc6749). **Note:** For the optional **scope** parameter, the Authentication API supports only the &#x60;*&#x60; value.
     * @param {Object} form Form parameters
     * @param {Object} opts Optional parameters
     * @param {String} opts.accept The media type the Authentication API should should use for the response. For example: &#39;Accept: application/x-www-form-urlencoded&#39;
     * @param {String} opts.authorization Basic authorization. For example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39;
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/DefaultOAuth2AccessToken} and HTTP response
     */
    async retrieveToken(form, opts = {}) {
        this._log(`Retrieving auth token based on grant_type=${form['grant_type']}`);
        if (form === undefined || form === null) {
            throw new Error("Missing the required parameter 'form' when calling retrieveToken");
        }
        let headerParams = {
            'Accept': opts['accept'],
            'Authorization': opts['authorization']
        };
        let contentTypes = ['application/x-www-form-urlencoded'];
        let accepts = ['application/json'];
        let returnType = DefaultOAuth2AccessToken;
        return this.client.callApi('/oauth/token', 'POST', {}, {}, {}, headerParams, form, null, [], contentTypes, accepts, returnType)
            .then(responseAndData => {
                return responseAndData.data;
            });
    }

    /**
     * Perform authorization
     * Perform authorization based on the code grant type &amp;mdash; either Authorization Code Grant or Implicit Grant. For more information, see [Authorization Endpoint](https://tools.ietf.org/html/rfc6749#section-3.1). **Note:** For the optional **scope** parameter, the Authentication API supports only the &#x60;*&#x60; value.
     * @param {String} clientId The ID of the application or service that is registered as the client. You&#39;ll need to get this value from your PureEngage Cloud representative.
     * @param {String} redirectUri The URI that you want users to be redirected to after entering valid credentials during an Implicit or Authorization Code grant. The Authentication API includes this as part of the URI it returns in the &#39;Location&#39; header.
     * @param {module:model/String} responseType The response type to let the Authentication API know which grant flow you&#39;re using. Possible values are &#x60;code&#x60; for Authorization Code Grant or &#x60;token&#x60; for Implicit Grant. For more information about this parameter, see [Response Type](https://tools.ietf.org/html/rfc6749#section-3.1.1).
     * @param {Object} opts Optional parameters
     * @param {String} opts.authorization Basic authorization. For example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39;
     * @param {Boolean} opts.hideTenant Hide the **tenant** field in the UI for Authorization Code Grant. (default to false)
     * @param {module:model/String} opts.scope The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value.
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}
     */
    async authorize(clientId, redirectUri, responseType, opts) {
        this._log(`Performing authorization: client_id=${clientId}, redirect_uri=${redirectUri}, response_type=${responseType}, opts=${opts}`);
        return (await this.authApi.authorize(clientId, redirectUri, responseType, opts));
    }

    /**
     * Change password
     * Change the user&#39;s password.
     * @param {module:model/ChangePasswordOperation} request request
     * @param {Object} opts Optional parameters
     * @param {String} opts.authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;  (default to bearer)
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    async changePassword(request, opts) {
        this._log(`Changing password`);
        return (await this.authApi.changePassword({data: request}, opts));
    }

    /**
     * Get OpenID user information by access token
     * Get information about a user by their OAuth 2 access token.
     * @param {String} authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/OpenIdUserInfo}
     */
    async getUserInfoOpenid(authorization) {
        this._log(`Getting OpenID user information`);
        return (await this.authApi.getInfo(authorization));
    }

    /**
     * Get user information by access token
     * Get information about a user by their OAuth 2 access token.
     * @param {String} authorization The OAuth 2 bearer access token. For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/CloudUserDetails}
     */
    async getUserInfo(authorization) {
        this._log(`Getting user information`);
        return (await this.authApi.getInfo1(authorization));
    }

    /**
     * getJwtInfo
     * @param {String} authorization The OAuth 2 bearer access token. For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/ApiResponse} and HTTP response
     */
    async getUserInfoJwt(authorization) {
        this._log(`Getting jwt user information`);
        return (await this.authApi.getJwtInfoUsingGET(authorization));
    }

    /**
     * Check connection
     * Return 200 if user is authenticated otherwise 403
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    async ping() {
        this._log(`Ping to keep session alive`);
        return (await this.authApi.ping());
    }

    /**
     * Sign-out a logged in user
     * Sign-out the current user and invalidate either the current token or all tokens associated with the user.
     * @param {String} authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;
     * @param {Object} opts Optional parameters
     * @param {Boolean} opts.global Specifies whether to invalidate all tokens for the current user (&#x60;true&#x60;) or only the current token (&#x60;false&#x60;).
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    async signOutPost(authorization, opts) {
        this._log(`Sign out the user`);
        return (await this.authApi.signOut(authorization, opts));
    }

    /**
     * Sign-out a logged in user
     * Sign-out the current user and invalidate either the current token or all tokens associated with the user.
     * @param {String} authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;
     * @param {Object} opts Optional parameters
     * @param {Boolean} opts.global Specifies whether to invalidate all tokens for the current user (&#x60;true&#x60;) or only the current token (&#x60;false&#x60;).
     * @param {String} opts.redirectUri Specifies the URI where the browser is redirected after sign-out is successful.
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    async signOutGet(authorization, opts) {
        this._log(`Sign out the user`);
        return (await this.authApi.signOut1(authorization, opts))
    }
    
}

module.exports = AuthenticationApi;
