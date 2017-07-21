/**
 * Authorization API
 * Authorization API
 *
 * OpenAPI spec version: 9.0.000.00.598
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.AuthorizationApi) {
      root.AuthorizationApi = {};
    }
    root.AuthorizationApi.DefaultOAuth2AccessToken = factory(root.AuthorizationApi.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';




  /**
   * The DefaultOAuth2AccessToken model module.
   * @module model/DefaultOAuth2AccessToken
   * @version 9.0.000.00.598
   */

  /**
   * Constructs a new <code>DefaultOAuth2AccessToken</code>.
   * @alias module:model/DefaultOAuth2AccessToken
   * @class
   */
  var exports = function() {
    var _this = this;





  };

  /**
   * Constructs a <code>DefaultOAuth2AccessToken</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DefaultOAuth2AccessToken} obj Optional instance to populate.
   * @return {module:model/DefaultOAuth2AccessToken} The populated <code>DefaultOAuth2AccessToken</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('access_token')) {
        obj['access_token'] = ApiClient.convertToType(data['access_token'], 'String');
      }
      if (data.hasOwnProperty('expires_in')) {
        obj['expires_in'] = ApiClient.convertToType(data['expires_in'], 'Number');
      }
      if (data.hasOwnProperty('id_token')) {
        obj['id_token'] = ApiClient.convertToType(data['id_token'], 'String');
      }
      if (data.hasOwnProperty('token_type')) {
        obj['token_type'] = ApiClient.convertToType(data['token_type'], 'String');
      }
    }
    return obj;
  }

  /**
   * the access token
   * @member {String} access_token
   */
  exports.prototype['access_token'] = undefined;
  /**
   * timeout (in seconds) before token expiration
   * @member {Number} expires_in
   */
  exports.prototype['expires_in'] = undefined;
  /**
   * id_token, see JWT standard for more details
   * @member {String} id_token
   */
  exports.prototype['id_token'] = undefined;
  /**
   * the type of access token, always 'bearer'
   * @member {String} token_type
   */
  exports.prototype['token_type'] = undefined;



  return exports;
}));


