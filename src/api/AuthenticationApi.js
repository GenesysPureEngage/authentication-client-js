/**
 * Authorization API
 * Authorization API
 *
 * OpenAPI spec version: 9.0.000.00.dev
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 *
 * Swagger Codegen version: 2.2.3
 *
 * Do not edit the class manually.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/ApiResponse', 'model/AuthSchemeLookupOperation', 'model/ChangePasswordOperation', 'model/CloudUserDetails', 'model/DefaultOAuth2AccessToken', 'model/ErrorResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('../model/ApiResponse'), require('../model/AuthSchemeLookupOperation'), require('../model/ChangePasswordOperation'), require('../model/CloudUserDetails'), require('../model/DefaultOAuth2AccessToken'), require('../model/ErrorResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.AuthorizationApi) {
      root.AuthorizationApi = {};
    }
    root.AuthorizationApi.AuthenticationApi = factory(root.AuthorizationApi.ApiClient, root.AuthorizationApi.ApiResponse, root.AuthorizationApi.AuthSchemeLookupOperation, root.AuthorizationApi.ChangePasswordOperation, root.AuthorizationApi.CloudUserDetails, root.AuthorizationApi.DefaultOAuth2AccessToken, root.AuthorizationApi.ErrorResponse);
  }
}(this, function(ApiClient, ApiResponse, AuthSchemeLookupOperation, ChangePasswordOperation, CloudUserDetails, DefaultOAuth2AccessToken, ErrorResponse) {
  'use strict';

  /**
   * Authentication service.
   * @module api/AuthenticationApi
   * @version 9.0.000.00.dev
   */

  /**
   * Constructs a new AuthenticationApi. 
   * @alias module:api/AuthenticationApi
   * @class
   * @param {module:ApiClient} apiClient Optional API client implementation to use,
   * default to {@link module:ApiClient#instance} if unspecified.
   */
  var exports = function(apiClient) {
    this.apiClient = apiClient || ApiClient.instance;



    /**
     * Endpoint to perform authorization
     * See http://callistaenterprise.se/blogg/teknik/2015/04/27/building-microservices-part-3-secure-APIs-with-OAuth/, We support implicit_grant  Implicit grant example:   curl -v -u genesys\\\\agent:password -XGET &#39;http://localhost:8095/auth/v3/oauth/authorize?response_type&#x3D;token &amp; client_id&#x3D;external_api_client &amp; scope&#x3D;openid &amp; redirect_uri&#x3D;http://localhost/  In this sample external_api_client is client_id of client with allowed **implicit** grant typeplease note that Location header will contain URI which is constructed from redirect_uri and contains access_code or auth_code and other optional info, sample:  Location: http://localhost#access_token&#x3D;76c785dc-ae3d-4569-8c79-cf4f23d70a07&amp;token_type&#x3D;bearer&amp;expires_in&#x3D;43199
     * @param {module:model/String} responseType Response type
     * @param {String} clientId Client ID (id of application/service registered as client in IDP)
     * @param {String} redirectUri Redirect URI - will be the part of URL returned in &#39;Location&#39; header
     * @param {Object} opts Optional parameters
     * @param {String} opts.authorization Basic authorization. Example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39;
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing HTTP response
     */
    this.authorizeWithHttpInfo = function(responseType, clientId, redirectUri, opts) {
      opts = opts || {};
      var postBody = null;

      // verify the required parameter 'responseType' is set
      if (responseType === undefined || responseType === null) {
        throw new Error("Missing the required parameter 'responseType' when calling authorize");
      }

      // verify the required parameter 'clientId' is set
      if (clientId === undefined || clientId === null) {
        throw new Error("Missing the required parameter 'clientId' when calling authorize");
      }

      // verify the required parameter 'redirectUri' is set
      if (redirectUri === undefined || redirectUri === null) {
        throw new Error("Missing the required parameter 'redirectUri' when calling authorize");
      }


      var pathParams = {
      };
      var queryParams = {
        'response_type': responseType,
        'client_id': clientId,
        'redirect_uri': redirectUri
      };
      var headerParams = {
        'Authorization': opts['authorization']
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = null;

      return this.apiClient.callApi(
        '/auth/v3/oauth/authorize', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Endpoint to perform authorization
     * See http://callistaenterprise.se/blogg/teknik/2015/04/27/building-microservices-part-3-secure-APIs-with-OAuth/, We support implicit_grant  Implicit grant example:   curl -v -u genesys\\\\agent:password -XGET &#39;http://localhost:8095/auth/v3/oauth/authorize?response_type&#x3D;token &amp; client_id&#x3D;external_api_client &amp; scope&#x3D;openid &amp; redirect_uri&#x3D;http://localhost/  In this sample external_api_client is client_id of client with allowed **implicit** grant typeplease note that Location header will contain URI which is constructed from redirect_uri and contains access_code or auth_code and other optional info, sample:  Location: http://localhost#access_token&#x3D;76c785dc-ae3d-4569-8c79-cf4f23d70a07&amp;token_type&#x3D;bearer&amp;expires_in&#x3D;43199
     * @param {module:model/String} responseType Response type
     * @param {String} clientId Client ID (id of application/service registered as client in IDP)
     * @param {String} redirectUri Redirect URI - will be the part of URL returned in &#39;Location&#39; header
     * @param {Object} opts Optional parameters
     * @param {String} opts.authorization Basic authorization. Example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39;
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}
     */
    this.authorize = function(responseType, clientId, redirectUri, opts) {
      return this.authorizeWithHttpInfo(responseType, clientId, redirectUri, opts)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Change password
     * Change user&#39;s password
     * @param {module:model/ChangePasswordOperation} request request
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/ApiResponse} and HTTP response
     */
    this.changePasswordWithHttpInfo = function(request) {
      var postBody = request;

      // verify the required parameter 'request' is set
      if (request === undefined || request === null) {
        throw new Error("Missing the required parameter 'request' when calling changePassword");
      }


      var pathParams = {
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = ApiResponse;

      return this.apiClient.callApi(
        '/auth/v3/change-password', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Change password
     * Change user&#39;s password
     * @param {module:model/ChangePasswordOperation} request request
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    this.changePassword = function(request) {
      return this.changePasswordWithHttpInfo(request)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Get user principal by OAUTH toke
     * This endpoint is called by oAuth2 clients to retrieve the principal by oAuth access token
     * @param {String} authorization OAuth 2.0 Bearer Token. Example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot; 
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/CloudUserDetails} and HTTP response
     */
    this.getInfoWithHttpInfo = function(authorization) {
      var postBody = null;

      // verify the required parameter 'authorization' is set
      if (authorization === undefined || authorization === null) {
        throw new Error("Missing the required parameter 'authorization' when calling getInfo");
      }


      var pathParams = {
      };
      var queryParams = {
      };
      var headerParams = {
        'Authorization': authorization
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = CloudUserDetails;

      return this.apiClient.callApi(
        '/auth/v3/userinfo', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Get user principal by OAUTH toke
     * This endpoint is called by oAuth2 clients to retrieve the principal by oAuth access token
     * @param {String} authorization OAuth 2.0 Bearer Token. Example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot; 
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/CloudUserDetails}
     */
    this.getInfo = function(authorization) {
      return this.getInfoWithHttpInfo(authorization)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Form-based authentication
     * Endpoint to perform form-based authentication
     * @param {Object} opts Optional parameters
     * @param {String} opts.username User name - should be in the format of &#39;domain\\username&#39;
     * @param {String} opts.password Password
     * @param {String} opts.domain Domain - used for SAML login only
     * @param {module:model/String} opts.saml SAML - flag indication saml login
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing HTTP response
     */
    this.loginWithHttpInfo = function(opts) {
      opts = opts || {};
      var postBody = null;


      var pathParams = {
      };
      var queryParams = {
        'username': opts['username'],
        'password': opts['password'],
        'domain': opts['domain'],
        'saml': opts['saml']
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['*/*'];
      var returnType = null;

      return this.apiClient.callApi(
        '/sign-in', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Form-based authentication
     * Endpoint to perform form-based authentication
     * @param {Object} opts Optional parameters
     * @param {String} opts.username User name - should be in the format of &#39;domain\\username&#39;
     * @param {String} opts.password Password
     * @param {String} opts.domain Domain - used for SAML login only
     * @param {module:model/String} opts.saml SAML - flag indication saml login
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}
     */
    this.login = function(opts) {
      return this.loginWithHttpInfo(opts)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Logout user
     * This endpoint is called by oAuth2 clients to logout user
     * @param {String} authorization OAuth 2.0 Bearer Token. Example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot; 
     * @param {Object} opts Optional parameters
     * @param {Boolean} opts.global If set all tokens for current user will be invalidated, otherwise only current token will be invalidated.
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/ApiResponse} and HTTP response
     */
    this.logoutWithHttpInfo = function(authorization, opts) {
      opts = opts || {};
      var postBody = null;

      // verify the required parameter 'authorization' is set
      if (authorization === undefined || authorization === null) {
        throw new Error("Missing the required parameter 'authorization' when calling logout");
      }


      var pathParams = {
      };
      var queryParams = {
        'global': opts['global']
      };
      var headerParams = {
        'Authorization': authorization
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = ApiResponse;

      return this.apiClient.callApi(
        '/auth/v3/sign-out', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Logout user
     * This endpoint is called by oAuth2 clients to logout user
     * @param {String} authorization OAuth 2.0 Bearer Token. Example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot; 
     * @param {Object} opts Optional parameters
     * @param {Boolean} opts.global If set all tokens for current user will be invalidated, otherwise only current token will be invalidated.
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    this.logout = function(authorization, opts) {
      return this.logoutWithHttpInfo(authorization, opts)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Endpoint to retrieve token
     * Can be called directly for Client Credential and Resource Owner Code flow.  Resource Owner example:   &#x60;curl client_name:client_secret@localhost:8095/auth/v3/oauth/token -d grant_type&#x3D;password -d client_id&#x3D;external_api_client-d scope&#x3D;openid -d username&#x3D;domain\\\\user -d password&#x3D;password&#x60;   Client credentials example:   &#x60;curl client_name:client_secret@localhost:8095/auth/v3/oauth/token -d grant_type&#x3D;client_credentials -d scope&#x3D;openid&#x60;
     * @param {module:model/String} grantType Grant type
     * @param {module:model/String} scope Scope
     * @param {Object} opts Optional parameters
     * @param {String} opts.authorization Basic authorization. Example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39;
     * @param {String} opts.clientId Client ID
     * @param {String} opts.username End-User user name
     * @param {String} opts.password End-User password
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/DefaultOAuth2AccessToken} and HTTP response
     */
    this.retrieveTokenWithHttpInfo = function(grantType, scope, opts) {
      opts = opts || {};
      var postBody = null;

      // verify the required parameter 'grantType' is set
      if (grantType === undefined || grantType === null) {
        throw new Error("Missing the required parameter 'grantType' when calling retrieveToken");
      }

      // verify the required parameter 'scope' is set
      if (scope === undefined || scope === null) {
        throw new Error("Missing the required parameter 'scope' when calling retrieveToken");
      }


      var pathParams = {
      };
      var queryParams = {
      };
      var headerParams = {
        'authorization': opts['authorization']
      };
      var formParams = {
        'grant_type': grantType,
        'scope': scope,
        'client_id': opts['clientId'],
        'username': opts['username'],
        'password': opts['password']
      };

      var authNames = [];
      var contentTypes = ['application/x-www-form-urlencoded'];
      var accepts = ['application/json'];
      var returnType = DefaultOAuth2AccessToken;

      return this.apiClient.callApi(
        '/auth/v3/oauth/token', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Endpoint to retrieve token
     * Can be called directly for Client Credential and Resource Owner Code flow.  Resource Owner example:   &#x60;curl client_name:client_secret@localhost:8095/auth/v3/oauth/token -d grant_type&#x3D;password -d client_id&#x3D;external_api_client-d scope&#x3D;openid -d username&#x3D;domain\\\\user -d password&#x3D;password&#x60;   Client credentials example:   &#x60;curl client_name:client_secret@localhost:8095/auth/v3/oauth/token -d grant_type&#x3D;client_credentials -d scope&#x3D;openid&#x60;
     * @param {module:model/String} grantType Grant type
     * @param {module:model/String} scope Scope
     * @param {Object} opts Optional parameters
     * @param {String} opts.authorization Basic authorization. Example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39;
     * @param {String} opts.clientId Client ID
     * @param {String} opts.username End-User user name
     * @param {String} opts.password End-User password
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/DefaultOAuth2AccessToken}
     */
    this.retrieveToken = function(grantType, scope, opts) {
      return this.retrieveTokenWithHttpInfo(grantType, scope, opts)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Show logout
     * Show logout status
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link Object} and HTTP response
     */
    this.showLogoutWithHttpInfo = function() {
      var postBody = null;


      var pathParams = {
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = Object;

      return this.apiClient.callApi(
        '/auth/v3/signed-out', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Show logout
     * Show logout status
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link Object}
     */
    this.showLogout = function() {
      return this.showLogoutWithHttpInfo()
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }


    /**
     * Get authentication scheme
     * Get authentication scheme by user name or tenant name
     * @param {module:model/AuthSchemeLookupOperation} lookupOperation lookupOperation
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with an object containing data of type {@link module:model/ApiResponse} and HTTP response
     */
    this.tenantInfoWithHttpInfo = function(lookupOperation) {
      var postBody = lookupOperation;

      // verify the required parameter 'lookupOperation' is set
      if (lookupOperation === undefined || lookupOperation === null) {
        throw new Error("Missing the required parameter 'lookupOperation' when calling tenantInfo");
      }


      var pathParams = {
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = ApiResponse;

      return this.apiClient.callApi(
        '/auth/v3/auth-scheme', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Get authentication scheme
     * Get authentication scheme by user name or tenant name
     * @param {module:model/AuthSchemeLookupOperation} lookupOperation lookupOperation
     * @return {Promise} a {@link https://www.promisejs.org/|Promise}, with data of type {@link module:model/ApiResponse}
     */
    this.tenantInfo = function(lookupOperation) {
      return this.tenantInfoWithHttpInfo(lookupOperation)
        .then(function(response_and_data) {
          return response_and_data.data;
        });
    }
  };

  return exports;
}));
