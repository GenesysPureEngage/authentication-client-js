# Authentication Client Library

The Authentication Client Library is a Node.js wrapper for the [Authentication API](https://developer.genhtcc.com/api/reference/authentication/) that makes it easier to code against the API. The library provides much of the supporting code needed to make HTTP requests and process HTTP responses.

The library is hosted on [GitHub](https://github.com/GenesysPureEngage/authentication-client-js) and Genesys welcomes pull requests for corrections.

## Install

Genesys recommends that you install the Authentication Client Library for Node.js with [NPM](https://npmjs.org/). Run the following command to install the library:

```
npm i genesys-authentication-client-js
```

## Related Links

* Learn more about the [Authentication API](https://developer.genhtcc.com/api/reference/authentication/).
* Learn more about the [Authentication Client Library](https://developer.genhtcc.com/api/client-libraries/authentication/).

## Classes

The Authentication Client Library includes one main class, [AuthenticationApi](https://developer.genhtcc.com/api/client-libraries/authentication/js/AuthenticationApi/index.html). This class contains all the resources and events that are part of the Authentication API, along with all the methods you need to access the API functionality.

## Examples

Here's an example of how you can use the Authentication Client Library to authenticate using the [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3) type.

``` javascript
const authentication = require('genesys-authentication-client-js');

const apiKey = "<apiKey>";
const apiUrl = "<apiUrl>";

const client = new authentication.ApiClient();
client.basePath = `${apiUrl}/auth/v3`;
client.defaultHeaders = {'x-api-key': apiKey};
client.enableCookies = true;

const agentUsername = "<agentUsername>";
const agentPassword = "<agentPassword>";
const clientId = "<clientId>";
const clientSecret = "<clientSecret>";

const authApi = new authentication.AuthenticationApi(client);
const opts = {
    authentication: "Basic " + new Buffer(`${clientId}:${clientSecret}`).toString("base64"),
    clientId: clientId,
    scope: '*',
    username: agentUsername,
    password: agentPassword
};

authApi.retrieveTokenWithHttpInfo("password", opts).then(resp => {
    const data = resp.response.body;
    const accessToken = data.access_token;
    if(!accessToken) {
        throw new Error('Cannot get access token');
    }

    return accessToken;
}).then(token => {
    //Initialize the API with token
    // ...
}).catch(console.error);
```

For usage examples for each method available in the library, see the documentation for the [AuthenticationAPi](https://developer.genhtcc.com/api/client-libraries/authentication/js/AuthenticationApi/index.html) class.