**This is not an officially supported Google product.**

This repository contains several demos to integrate with Google Identity
(https://developers.google.com/identity) products.

# demo-for-google-identity

## Source Code Headers

Every file containing source code must include copyright and license
information. This includes any JS/CSS files that you might be serving out to
browsers. (This is to help well-intentioned people avoid accidental copying that
doesn't comply with the license.)

Apache header:

    Copyright 2020 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

## Current Progress

Finish Basic Login Filter using Guice-Servlet.

Finish Basic AuthorizationEndpoint, ConsentEndpoint, TokenEndpoint, TokenRevokeEndpoint, RiscDocEndpoint and JwkEndpoint.

Authorization Code Flow and Implicit Flow are all workable now.

Support token revocation.

Support Risc.

In memory user information storage with sha256 based hashing on password.

In memory client information storage with sha256 based hashing on secret.

Two test user added:
 
username	password 
 
user		123456 
 
user1 		12345678 

One test client added:
 
ClientID	secret      scope      redirect_uri 

google		secret       read     http://www.google.com  

The project can be reached at

Login Page: https://gal-2020-summer-intern.appspot.com/login

Resource Page: https://gal-2020-summer-intern.appspot.com/resource/user

Authorization Endpoint: https://gal-2020-summer-intern.appspot.com/oauth2/authorize

Token Endpoint: https://gal-2020-summer-intern.appspot.com/oauth2/authorize

RiscDoc Endpoint: https://gal-2020-summer-intern.appspot.com/oauth2/risc/.well-know/risc-configuration

Risc Issuer: https://gal-2020-summer-intern.appspot.com/oauth2/risc

Risc Jwk Endpoint: https://gal-2020-summer-intern.appspot.com/oauth2/risc/key

All resources under /resource is protected (currently only have /resource/user)

How to run it:
1. Download, install maven from https://maven.apache.org/
2. Download, install google cloud SDK following https://cloud.google.com/sdk/docs/quickstarts
3. Download, install Protocol Buffers from https://github.com/protocolbuffers/protobuf/releases/tag/v3.12.3
4. Dompile all proto files in src/main/resources/proto
5. Change web url (for risc issuer and key) in appengine-web.xml by setting system env.
6. Test it locally or on app engine

locally:

mvn package appengine:run

reach localhost:8080

app engine:

mvn package appengine:deploy 

reach your appengine website

