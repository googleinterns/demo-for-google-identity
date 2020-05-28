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

Finish Basic Login Filter using Guice-Servlet

In memory user information storage with md5 based encryption on password.

Two test user added:
username	password
user		123456
user1 		12345678

The project can be reached at

http://gal-2020-summer-intern.appspot.com/

All resources under /resource is protected(currently only have /resource/user)

How to run it:
1. download, install maven from https://maven.apache.org/
2. download, install google cloud SDK following https://cloud.google.com/sdk/docs/quickstarts
3. Test it locally or on app engine
locally:
mvn package appengine:run

reach localhost:8080/

app engine:
mvn package appengine:deploy 

reach your appengine website