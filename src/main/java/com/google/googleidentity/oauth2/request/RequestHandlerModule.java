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

package com.google.googleidentity.oauth2.request;

import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.inject.AbstractModule;
import com.google.inject.multibindings.MapBinder;

public class RequestHandlerModule extends AbstractModule {

  @Override
  protected void configure() {
    MapBinder<GrantType, RequestHandler> mapBinder =
        MapBinder.newMapBinder(
            binder(), GrantType.class, RequestHandler.class);
    mapBinder.addBinding(GrantType.AUTHORIZATION_CODE).to(AuthorizationCodeRequestHandler.class);
    mapBinder.addBinding(GrantType.IMPLICIT).to(ImplicitRequestHandler.class);
    mapBinder.addBinding(GrantType.REFRESH_TOKEN).to(RefreshTokenRequestHandler.class);
    mapBinder.addBinding(GrantType.JWT_ASSERTION).to(JwtAssertionRequestHandler.class);
    bind(RequestHandler.class).to(MultipleRequestHandler.class);
  }
}
