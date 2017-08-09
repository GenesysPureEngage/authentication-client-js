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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.AuthorizationApi) {
      root.AuthorizationApi = {};
    }
    root.AuthorizationApi.BaseClientDetails = factory(root.AuthorizationApi.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';




  /**
   * The BaseClientDetails model module.
   * @module model/BaseClientDetails
   * @version 9.0.000.00.dev
   */

  /**
   * Constructs a new <code>BaseClientDetails</code>.
   * @alias module:model/BaseClientDetails
   * @class
   */
  var exports = function() {
    var _this = this;











  };

  /**
   * Constructs a <code>BaseClientDetails</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/BaseClientDetails} obj Optional instance to populate.
   * @return {module:model/BaseClientDetails} The populated <code>BaseClientDetails</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('access_token_validity')) {
        obj['access_token_validity'] = ApiClient.convertToType(data['access_token_validity'], 'Number');
      }
      if (data.hasOwnProperty('authorities')) {
        obj['authorities'] = ApiClient.convertToType(data['authorities'], ['String']);
      }
      if (data.hasOwnProperty('authorized_grant_types')) {
        obj['authorized_grant_types'] = ApiClient.convertToType(data['authorized_grant_types'], 'String');
      }
      if (data.hasOwnProperty('autoapprove')) {
        obj['autoapprove'] = ApiClient.convertToType(data['autoapprove'], 'String');
      }
      if (data.hasOwnProperty('client_id')) {
        obj['client_id'] = ApiClient.convertToType(data['client_id'], 'String');
      }
      if (data.hasOwnProperty('client_secret')) {
        obj['client_secret'] = ApiClient.convertToType(data['client_secret'], 'String');
      }
      if (data.hasOwnProperty('redirect_uri')) {
        obj['redirect_uri'] = ApiClient.convertToType(data['redirect_uri'], ['String']);
      }
      if (data.hasOwnProperty('refresh_token_validity')) {
        obj['refresh_token_validity'] = ApiClient.convertToType(data['refresh_token_validity'], 'Number');
      }
      if (data.hasOwnProperty('resource_ids')) {
        obj['resource_ids'] = ApiClient.convertToType(data['resource_ids'], 'String');
      }
      if (data.hasOwnProperty('scope')) {
        obj['scope'] = ApiClient.convertToType(data['scope'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {Number} access_token_validity
   */
  exports.prototype['access_token_validity'] = undefined;
  /**
   * @member {Array.<String>} authorities
   */
  exports.prototype['authorities'] = undefined;
  /**
   * @member {String} authorized_grant_types
   */
  exports.prototype['authorized_grant_types'] = undefined;
  /**
   * @member {String} autoapprove
   */
  exports.prototype['autoapprove'] = undefined;
  /**
   * @member {String} client_id
   */
  exports.prototype['client_id'] = undefined;
  /**
   * @member {String} client_secret
   */
  exports.prototype['client_secret'] = undefined;
  /**
   * @member {Array.<String>} redirect_uri
   */
  exports.prototype['redirect_uri'] = undefined;
  /**
   * @member {Number} refresh_token_validity
   */
  exports.prototype['refresh_token_validity'] = undefined;
  /**
   * @member {String} resource_ids
   */
  exports.prototype['resource_ids'] = undefined;
  /**
   * @member {String} scope
   */
  exports.prototype['scope'] = undefined;



  return exports;
}));


