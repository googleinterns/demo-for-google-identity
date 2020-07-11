/*
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
*/

package com.google.googleidentity.oauth2.config;

import com.google.googleidentity.oauth2.authorizationcode.AuthorizationCodeModule;
import com.google.googleidentity.oauth2.request.RequestHandlerModule;
import com.google.googleidentity.oauth2.token.TokenModule;
import com.google.inject.AbstractModule;

/** Module for OAuth2Server */
public class OAuth2ServerModule extends AbstractModule {

  @Override
  protected void configure() {
    install(new AuthorizationCodeModule());
    install(new TokenModule());
    install(new RequestHandlerModule());
  }
}
