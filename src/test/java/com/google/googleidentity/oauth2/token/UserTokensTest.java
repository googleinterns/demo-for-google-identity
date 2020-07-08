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

package com.google.googleidentity.oauth2.token;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import org.junit.Test;

import java.time.Instant;
import java.util.UUID;

import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.Truth.assertThat;

public class UserTokensTest {
    private static final String CLIENTID = "clientid";
    private static final String SECRET = "secret";
    private static final String REDIRECT_URI = "http://www.google.com";

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI)
                    .addGrantTypes(GrantType.AUTHORIZATION_CODE)
                    .build();

    private static final String USERNAME = "111";

    OAuth2AccessToken TEST_ACCESS_TOKEN =
            OAuth2AccessToken.newBuilder()
                    .setClientId(CLIENTID)
                    .setUsername(USERNAME)
                    .setIsScoped(true)
                    .setExpiredTime(Instant.now().getEpochSecond())
                    .addAllScopes(CLIENT.getScopesList())
                    .build();




    @Test
    public void testAddAccessToken_canReadOut() {
        UserTokens user = new UserTokens(USERNAME);

        String tokenValue = UUID.randomUUID().toString();
        user.addAccessToken(CLIENTID, tokenValue, TEST_ACCESS_TOKEN);

        assertThat(user.readAccessToken(CLIENTID, tokenValue)).hasValue(TEST_ACCESS_TOKEN);

        assertThat(user.listAccessTokens(CLIENTID)).containsExactly(TEST_ACCESS_TOKEN);
    }

    @Test
    public void testSetRefreshToken_canReadOut() {
        UserTokens user = new UserTokens(USERNAME);

        String tokenString = UUID.randomUUID().toString();

        OAuth2RefreshToken TEST_REFRESH_TOKEN =
                OAuth2RefreshToken.newBuilder()
                        .setClientId(CLIENTID)
                        .setUsername(USERNAME)
                        .setIsScoped(true)
                        .addAllScopes(CLIENT.getScopesList())
                        .setRefreshToken(tokenString)
                        .build();

        user.setRefreshToken(CLIENTID, TEST_REFRESH_TOKEN);

        assertThat(user.getRefreshToken(CLIENTID)).hasValue(TEST_REFRESH_TOKEN);

        assertThat(user.readRefreshToken(CLIENTID, tokenString)).hasValue(TEST_REFRESH_TOKEN);

    }


    @Test
    public void testRevokeTokens_empty() {
        UserTokens user = new UserTokens(USERNAME);

        String tokenString = UUID.randomUUID().toString();

        OAuth2RefreshToken TEST_REFRESH_TOKEN =
                OAuth2RefreshToken.newBuilder()
                        .setClientId(CLIENTID)
                        .setUsername(USERNAME)
                        .setIsScoped(true)
                        .addAllScopes(CLIENT.getScopesList())
                        .setRefreshToken(tokenString)
                        .build();

        user.setRefreshToken(CLIENTID, TEST_REFRESH_TOKEN);

        user.revokeUserClientTokens(CLIENTID);

        assertThat(user.getRefreshToken(CLIENTID)).isEmpty();

        assertThat(user.isEmpty()).isTrue();

    }


    @Test
    public void testClearExpiredTokens_tokenRemoved() {
        UserTokens user = new UserTokens(USERNAME);

        String tokenString = UUID.randomUUID().toString();

        user.addAccessToken(CLIENTID, tokenString, TEST_ACCESS_TOKEN);

        user.clearExpiredTokens();

        assertThat(user.getRefreshToken(CLIENTID)).isEmpty();

    }
}
