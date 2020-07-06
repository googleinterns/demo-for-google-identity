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

import com.google.googleidentity.oauth2.authorizationcode.AuthorizationCodeRequestHandler;
import com.google.googleidentity.oauth2.authorizationcode.AuthorizationCodeService;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import java.util.HashMap;
import java.util.Map;

/**
 * Default request handler provider, will contain all type of handlers
 */
public class DefaultRequestHandlerProvider implements Provider<RequestHandler> {

    private final AuthorizationCodeService authorizationCodeService;

    private final OAuth2TokenService oauth2TokenService;

    private final ClientDetailsService clientDetailsService;

    private final UserDetailsService userDetailsService;

    @Inject
    public DefaultRequestHandlerProvider(AuthorizationCodeService authorizationCodeService,
                                  OAuth2TokenService oauth2TokenService,
                                  UserDetailsService userDetailsService,
                                  ClientDetailsService clientDetailsService) {
        this.authorizationCodeService = authorizationCodeService;
        this.oauth2TokenService = oauth2TokenService;
        this.userDetailsService = userDetailsService;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    @Singleton
    public RequestHandler get() {
        Map<String, RequestHandler> tokenProcessorMap = new HashMap<>();
        tokenProcessorMap.put(
                OAuth2Constants.GrantType.AUTHORIZATION_CODE,
                new AuthorizationCodeRequestHandler(
                        authorizationCodeService,
                        oauth2TokenService));
        return new MultipleRequestHandler(tokenProcessorMap);
    }
}