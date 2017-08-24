/**
 * Authorization API
 * Authorization API
 *
 * OpenAPI spec version: 9.0.000.00.718
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
    root.AuthorizationApi.GrantedAuthority = factory(root.AuthorizationApi.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';




  /**
   * The GrantedAuthority model module.
   * @module model/GrantedAuthority
   * @version 9.0.000.00.718
   */

  /**
   * Constructs a new <code>GrantedAuthority</code>.
   * @alias module:model/GrantedAuthority
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GrantedAuthority</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GrantedAuthority} obj Optional instance to populate.
   * @return {module:model/GrantedAuthority} The populated <code>GrantedAuthority</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('authority')) {
        obj['authority'] = ApiClient.convertToType(data['authority'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} authority
   */
  exports.prototype['authority'] = undefined;



  return exports;
}));


