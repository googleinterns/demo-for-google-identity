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

package com.google.googleidentity.oauth2.client.test;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;


public class TestClientModule extends AbstractModule {

    private static final String TESTCLIENTID = "google";
    private static final String TESTSECRET = "secret";
    private static final ImmutableList<String> TESTSCOPES = ImmutableList.of("read");
    private static final ImmutableList<String> TESTGRANTTYPES = ImmutableList.of(
            "authorization_code",
            "implicit",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:jwt-bearer");

    private static final String TESTREDIRECTURI = "http://www.google.com";

    @Override
    protected void configure(){
    }

    @Provides
    @Singleton
    public ClientDetailsService getClientDetailsService(
            InMemoryClientDetailsService clientDetailsService) {

        ClientDetails client =
                ClientDetails.newBuilder()
                        .setClientId(TESTCLIENTID)
                        .setSecret(Hashing.sha256()
                                .hashString(TESTSECRET, Charsets.UTF_8).toString())
                        .addAllScopes(TESTSCOPES)
                        .setIsScoped(true)
                        .addAllGrantTypes(TESTGRANTTYPES)
                        .addRedirectUris(TESTREDIRECTURI)
                        .build();
        clientDetailsService.addClient(client);
        return clientDetailsService;
    }
}



