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

(function(factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/ApiResponse', 'model/ApiResponseStatus', 'model/AuthSchemeLookupOperation', 'model/BaseClientDetails', 'model/ChangePasswordOperation', 'model/ClientDetails', 'model/CloudUserDetails', 'model/DefaultOAuth2AccessToken', 'model/ErrorResponse', 'model/GrantedAuthority', 'model/UserRole', 'api/AuthenticationApi', 'api/ClientAPIApi'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('./ApiClient'), require('./model/ApiResponse'), require('./model/ApiResponseStatus'), require('./model/AuthSchemeLookupOperation'), require('./model/BaseClientDetails'), require('./model/ChangePasswordOperation'), require('./model/ClientDetails'), require('./model/CloudUserDetails'), require('./model/DefaultOAuth2AccessToken'), require('./model/ErrorResponse'), require('./model/GrantedAuthority'), require('./model/UserRole'), require('./api/AuthenticationApi'), require('./api/ClientAPIApi'));
  }
}(function(ApiClient, ApiResponse, ApiResponseStatus, AuthSchemeLookupOperation, BaseClientDetails, ChangePasswordOperation, ClientDetails, CloudUserDetails, DefaultOAuth2AccessToken, ErrorResponse, GrantedAuthority, UserRole, AuthenticationApi, ClientAPIApi) {
  'use strict';

  /**
   * Authorization_API.<br>
   * The <code>index</code> module provides access to constructors for all the classes which comprise the public API.
   * <p>
   * An AMD (recommended!) or CommonJS application will generally do something equivalent to the following:
   * <pre>
   * var AuthorizationApi = require('index'); // See note below*.
   * var xxxSvc = new AuthorizationApi.XxxApi(); // Allocate the API class we're going to use.
   * var yyyModel = new AuthorizationApi.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * <em>*NOTE: For a top-level AMD script, use require(['index'], function(){...})
   * and put the application logic within the callback function.</em>
   * </p>
   * <p>
   * A non-AMD browser application (discouraged) might do something like this:
   * <pre>
   * var xxxSvc = new AuthorizationApi.XxxApi(); // Allocate the API class we're going to use.
   * var yyy = new AuthorizationApi.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * </p>
   * @module index
   * @version 9.0.000.00.dev
   */
  var exports = {
    /**
     * The ApiClient constructor.
     * @property {module:ApiClient}
     */
    ApiClient: ApiClient,
    /**
     * The ApiResponse model constructor.
     * @property {module:model/ApiResponse}
     */
    ApiResponse: ApiResponse,
    /**
     * The ApiResponseStatus model constructor.
     * @property {module:model/ApiResponseStatus}
     */
    ApiResponseStatus: ApiResponseStatus,
    /**
     * The AuthSchemeLookupOperation model constructor.
     * @property {module:model/AuthSchemeLookupOperation}
     */
    AuthSchemeLookupOperation: AuthSchemeLookupOperation,
    /**
     * The BaseClientDetails model constructor.
     * @property {module:model/BaseClientDetails}
     */
    BaseClientDetails: BaseClientDetails,
    /**
     * The ChangePasswordOperation model constructor.
     * @property {module:model/ChangePasswordOperation}
     */
    ChangePasswordOperation: ChangePasswordOperation,
    /**
     * The ClientDetails model constructor.
     * @property {module:model/ClientDetails}
     */
    ClientDetails: ClientDetails,
    /**
     * The CloudUserDetails model constructor.
     * @property {module:model/CloudUserDetails}
     */
    CloudUserDetails: CloudUserDetails,
    /**
     * The DefaultOAuth2AccessToken model constructor.
     * @property {module:model/DefaultOAuth2AccessToken}
     */
    DefaultOAuth2AccessToken: DefaultOAuth2AccessToken,
    /**
     * The ErrorResponse model constructor.
     * @property {module:model/ErrorResponse}
     */
    ErrorResponse: ErrorResponse,
    /**
     * The GrantedAuthority model constructor.
     * @property {module:model/GrantedAuthority}
     */
    GrantedAuthority: GrantedAuthority,
    /**
     * The UserRole model constructor.
     * @property {module:model/UserRole}
     */
    UserRole: UserRole,
    /**
     * The AuthenticationApi service constructor.
     * @property {module:api/AuthenticationApi}
     */
    AuthenticationApi: AuthenticationApi,
    /**
     * The ClientAPIApi service constructor.
     * @property {module:api/ClientAPIApi}
     */
    ClientAPIApi: ClientAPIApi
  };

  return exports;
}));
