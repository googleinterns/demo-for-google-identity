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

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.authorizationcode.AuthorizationCodeService;
import com.google.googleidentity.oauth2.authorizationcode.CodeStore;
import com.google.googleidentity.oauth2.authorizationcode.InMemoryCodeStore;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;

/**
 * Module for OAuth2Server
 */
public class OAuth2ServerModule extends AbstractModule {

    @Override
    protected void configure(){
        bind(CodeStore.class).to(InMemoryCodeStore.class);
    }

    @Provides
    @Singleton
    public AuthorizationCodeService getAuthorizationCodeService(
            AuthorizationCodeService authorizationCodeService) {
        authorizationCodeService.setCodeLength(10);
        return authorizationCodeService;
    }

}
