/**
 * Authentication API
 * Authentication API
 *
 * OpenAPI spec version: 9.0.000.30.1613
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 *
 * Swagger Codegen version: 2.3.1
 *
 * Do not edit the class manually.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/UserRole'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./UserRole'));
  } else {
    // Browser globals (root is window)
    if (!root.AuthenticationApi) {
      root.AuthenticationApi = {};
    }
    root.AuthenticationApi.OpenIdUserInfo = factory(root.AuthenticationApi.ApiClient, root.AuthenticationApi.UserRole);
  }
}(this, function(ApiClient, UserRole) {
  'use strict';




  /**
   * The OpenIdUserInfo model module.
   * @module model/OpenIdUserInfo
   * @version 9.0.000.30.1613
   */

  /**
   * Constructs a new <code>OpenIdUserInfo</code>.
   * This class describes the user in the system. Applicable to different entities (contact-center level user, application/service, cloud system admin)
   * @alias module:model/OpenIdUserInfo
   * @class
   * @param authorities {module:model/UserRole} Authorities assigned to the user.
   */
  var exports = function(authorities) {
    var _this = this;


    _this['authorities'] = authorities;








  };

  /**
   * Constructs a <code>OpenIdUserInfo</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OpenIdUserInfo} obj Optional instance to populate.
   * @return {module:model/OpenIdUserInfo} The populated <code>OpenIdUserInfo</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('aud')) {
        obj['aud'] = ApiClient.convertToType(data['aud'], 'String');
      }
      if (data.hasOwnProperty('authorities')) {
        obj['authorities'] = UserRole.constructFromObject(data['authorities']);
      }
      if (data.hasOwnProperty('contact_center_id')) {
        obj['contact_center_id'] = ApiClient.convertToType(data['contact_center_id'], 'String');
      }
      if (data.hasOwnProperty('dbid')) {
        obj['dbid'] = ApiClient.convertToType(data['dbid'], 'Number');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('environment_id')) {
        obj['environment_id'] = ApiClient.convertToType(data['environment_id'], 'String');
      }
      if (data.hasOwnProperty('family_name')) {
        obj['family_name'] = ApiClient.convertToType(data['family_name'], 'String');
      }
      if (data.hasOwnProperty('given_name')) {
        obj['given_name'] = ApiClient.convertToType(data['given_name'], 'String');
      }
      if (data.hasOwnProperty('sub')) {
        obj['sub'] = ApiClient.convertToType(data['sub'], 'String');
      }
      if (data.hasOwnProperty('user_name')) {
        obj['user_name'] = ApiClient.convertToType(data['user_name'], 'String');
      }
    }
    return obj;
  }

  /**
   * OpenID Connect 'aud' claim. This is present if user authenticated with openid scope.
   * @member {String} aud
   */
  exports.prototype['aud'] = undefined;
  /**
   * Authorities assigned to the user.
   * @member {module:model/UserRole} authorities
   */
  exports.prototype['authorities'] = undefined;
  /**
   * OpenID Connect 'aud' claim. This is present if user authenticated with openid scope.
   * @member {String} contact_center_id
   */
  exports.prototype['contact_center_id'] = undefined;
  /**
   * The DBID of the corresponding user record in Configuration Server. This is present if the user belongs to a contact center.
   * @member {Number} dbid
   */
  exports.prototype['dbid'] = undefined;
  /**
   * OpenID Connect 'email' claim. This is present if user authenticated with openid scope.
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * OpenID Connect 'environment_id' claim. This is present if user authenticated with openid scope.
   * @member {String} environment_id
   */
  exports.prototype['environment_id'] = undefined;
  /**
   * OpenID Connect 'family_name' (last name) claim. This is present if user authenticated with openid scope.
   * @member {String} family_name
   */
  exports.prototype['family_name'] = undefined;
  /**
   * OpenID Connect 'given_name' (first name) claim. This is present if user authenticated with openid scope.
   * @member {String} given_name
   */
  exports.prototype['given_name'] = undefined;
  /**
   * OpenID Connect 'sub' claim. This is present if user authenticated with openid scope.
   * @member {String} sub
   */
  exports.prototype['sub'] = undefined;
  /**
   * OpenID Connect 'aud' claim. This is present if user authenticated with openid scope.
   * @member {String} user_name
   */
  exports.prototype['user_name'] = undefined;



  return exports;
}));


