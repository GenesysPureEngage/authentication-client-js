/**
 * Authentication API
 * Authentication API
 *
 * OpenAPI spec version: 9.0.000.39.1782
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 *
 * Swagger Codegen version: 2.4.5
 *
 * Do not edit the class manually.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/AuthSchemeLookupData'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./AuthSchemeLookupData'));
  } else {
    // Browser globals (root is window)
    if (!root.AuthenticationApi) {
      root.AuthenticationApi = {};
    }
    root.AuthenticationApi.ApiRequestOfAuthSchemeLookupData = factory(root.AuthenticationApi.ApiClient, root.AuthenticationApi.AuthSchemeLookupData);
  }
}(this, function(ApiClient, AuthSchemeLookupData) {
  'use strict';




  /**
   * The ApiRequestOfAuthSchemeLookupData model module.
   * @module model/ApiRequestOfAuthSchemeLookupData
   * @version 9.0.000.39.1782
   */

  /**
   * Constructs a new <code>ApiRequestOfAuthSchemeLookupData</code>.
   * @alias module:model/ApiRequestOfAuthSchemeLookupData
   * @class
   * @param data {module:model/AuthSchemeLookupData} 
   */
  var exports = function(data) {
    var _this = this;

    _this['data'] = data;

  };

  /**
   * Constructs a <code>ApiRequestOfAuthSchemeLookupData</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/ApiRequestOfAuthSchemeLookupData} obj Optional instance to populate.
   * @return {module:model/ApiRequestOfAuthSchemeLookupData} The populated <code>ApiRequestOfAuthSchemeLookupData</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('data')) {
        obj['data'] = AuthSchemeLookupData.constructFromObject(data['data']);
      }
      if (data.hasOwnProperty('operationId')) {
        obj['operationId'] = ApiClient.convertToType(data['operationId'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {module:model/AuthSchemeLookupData} data
   */
  exports.prototype['data'] = undefined;
  /**
   * Used for asynchronous operations to map request and response
   * @member {String} operationId
   */
  exports.prototype['operationId'] = undefined;



  return exports;
}));

