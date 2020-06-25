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
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.validator.AuthorizationEndpointRequestValidator;
import com.google.googleidentity.user.UserDetails;
import org.junit.Test;

import java.util.Optional;
import java.util.UUID;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link InMemoryOAuth2TokenService}
 */
public class InMemoryOAuth2TokenServiceTest {

    private static final String CLIENTID = "111";
    private static final String SECRET = "111";
    private static final String REDIRECT_URI = "http://www.google.com";

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI)
                    .addGrantTypes("authorization_code")
                    .build();

    private static final String USERNAME = "111";
    private static final String PASSWORD = "111";

    private static final UserDetails USER =
            UserDetails.newBuilder()
                    .setUsername(USERNAME)
                    .setPassword(Hashing.sha256()
                            .hashString(PASSWORD, Charsets.UTF_8).toString())
                    .build();


    OAuth2Request TESTREQUEST0 =
            OAuth2Request.newBuilder()
                    .setRequestAuth(
                            OAuth2Request.RequestAuth.newBuilder()
                                    .setClientId(CLIENTID)
                                    .setUsername(USERNAME)
                                    .build())
                    .setRequestBody(
                            OAuth2Request.RequestBody.newBuilder()
                                    .setIsScoped(true)
                                    .addAllScopes(CLIENT.getScopesList())
                                    .setResponseType("token")
                                    .setRefreshable(true)
                                    .setGrantType("authorization_code")
                                    .build())
                    .build();

    OAuth2Request TESTREQUEST1 =
            OAuth2Request.newBuilder()
                    .setRequestAuth(
                            OAuth2Request.RequestAuth.newBuilder()
                                    .setClientId(CLIENTID)
                                    .setUsername(USERNAME)
                                    .build())
                    .setRequestBody(
                            OAuth2Request.RequestBody.newBuilder()
                                    .setIsScoped(true)
                                    .addAllScopes(CLIENT.getScopesList())
                                    .setResponseType("token")
                                    .setRefreshable(false)
                                    .setGrantType("implicit")
                                    .build())
                    .build();


    @Test
    public void testGenerateAccessToken_correctInput_correctToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken expectedAccessToken =
                OAuth2AccessToken.newBuilder()
                        .setClientId(CLIENTID)
                        .setUsername(USERNAME)
                        .setIsScoped(true)
                        .addAllScopes(CLIENT.getScopesList())
                        .setRefreshable(true)
                        .build();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        assertThat(token).comparingExpectedFieldsOnly().isEqualTo(expectedAccessToken);

    }


    @Test
    public void testGenerateAccessToken_notRefreshable_noRefreshToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken expectedToken =
                OAuth2AccessToken.newBuilder()
                        .setRefreshable(false)
                        .build();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST1);


        assertThat(token).comparingExpectedFieldsOnly().isEqualTo(expectedToken);
    }

    @Test
    public void testRefreshToken_invalidRefreshToken_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        assertThat(tokenService.refreshToken(UUID.randomUUID().toString())).isEmpty();
    }

    @Test
    public void testRefreshToken_noThatRefreshToken_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST1);


        assertThat(tokenService.refreshToken(token.getAccessToken())).isEmpty();
    }

    @Test
    public void testRefreshToken_CorrectRefreshToken_returnNewToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);
        Optional<OAuth2AccessToken> token1 =
                tokenService.refreshToken(token.getRefreshToken());

        assertThat(token1).isPresent();

        // Ignore access_token value and expired_time
        assertThat(token).ignoringFields(1, 6).isEqualTo(token1.get());
    }

    @Test
    public void testReadAccessToken_correctInput_returnCorrectToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);
        Optional<OAuth2AccessToken> token1 =
                tokenService.readAccessToken(token.getAccessToken());

        assertThat(token1).isPresent();

        assertThat(token).isEqualTo(token1.get());
    }


    @Test
    public void testReadAccessToken_nonExistToken_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        Optional<OAuth2AccessToken> token =
                tokenService.readAccessToken(UUID.randomUUID().toString());

        assertThat(token).isEmpty();
    }


    @Test
    public void testReadAccessToken_invalidToken_returnCorrectToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);
        Optional<OAuth2AccessToken> token1 =
                tokenService.readAccessToken(token.getRefreshToken());

        assertThat(token1).isEmpty();
    }


    @Test
    public void testReadRefreshToken_correctInput_returnCorrectToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);
        Optional<OAuth2RefreshToken> token1 =
                tokenService.readRefreshToken(token.getRefreshToken());

        OAuth2RefreshToken expectedToken =
                OAuth2RefreshToken.newBuilder()
                        .setClientId(CLIENTID)
                        .setUsername(USERNAME)
                        .setIsScoped(CLIENT.getIsScoped())
                        .addAllScopes(CLIENT.getScopesList())
                        .build();
        assertThat(token1).isPresent();

        assertThat(token1.get()).comparingExpectedFieldsOnly().isEqualTo(expectedToken);
    }


    @Test
    public void testReadRefreshToken_nonExistToken_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST1);

        Optional<OAuth2RefreshToken> token1 =
                tokenService.readRefreshToken(token.getAccessToken());

        assertThat(token1).isEmpty();
    }


    @Test
    public void testReadRefreshToken_invalidToken_returnCorrectToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        Optional<OAuth2AccessToken> token =
                tokenService.readAccessToken(UUID.randomUUID().toString());

        assertThat(token).isEmpty();
    }

    @Test
    public void testListUserClient_correctInput_returnCorrectResult() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        assertThat(tokenService.listUserClient(USERNAME)).containsExactly(CLIENTID);

    }

    @Test
    public void testListUserClient_userLinkNoClient_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        assertThat(tokenService.listUserClient(USERNAME)).isEmpty();

    }


    @Test
    public void testListUserClientAccessTokens_correctInput_returnCorrectResult() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        assertThat(tokenService.listUserClientAccessTokens(USERNAME, CLIENTID))
                .containsExactly(token);
    }

    @Test
    public void testListUserClientAccessTokens_userLinkNoClient_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        assertThat(tokenService.listUserClientAccessTokens(USERNAME,CLIENTID)).isEmpty();

    }

    @Test
    public void testListUserClientRefreshTokens_correctInput_returnCorrectResult() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        OAuth2RefreshToken token1 = tokenService.readRefreshToken(token.getRefreshToken()).get();

        assertThat(tokenService.listUserClientRefreshTokens(USERNAME, CLIENTID))
                .containsExactly(token1);
    }
    @Test
    public void testListUserClientRefreshTokens_userLinkNoClient_returnEmpty() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        assertThat(tokenService.listUserClientRefreshTokens(USERNAME,CLIENTID)).isEmpty();

    }

    @Test
    public void testRevokeAccessToken_correctInput_returnTrueAndRemoveToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        assertThat(tokenService.revokeAccessToken(token.getAccessToken())).isTrue();

        assertThat(tokenService.readAccessToken(token.getAccessToken())).isEmpty();

        assertThat(tokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).isEmpty();

    }

    @Test
    public void testRevokeAccessToken_wrongOrInvalidAccessToken_returnFalse() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        assertThat(tokenService.revokeAccessToken(UUID.randomUUID().toString())).isFalse();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        assertThat(tokenService.revokeAccessToken(token.getRefreshToken())).isFalse();

    }



    @Test
    public void testRevokeRefreshToken_correctInput_returnTrueAndRemoveRefreshToken() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST0);

        assertThat(tokenService.revokeRefreshToken(token.getRefreshToken())).isTrue();

        assertThat(tokenService.readRefreshToken(token.getRefreshToken())).isEmpty();

        assertThat(tokenService.listUserClientRefreshTokens(USERNAME, CLIENTID)).isEmpty();

    }

    @Test
    public void testRevokeRefreshToken_wrongOrInvalidRefreshToken_returnFalse() {
        OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

        assertThat(tokenService.revokeRefreshToken(UUID.randomUUID().toString())).isFalse();

        OAuth2AccessToken token  = tokenService.generateAccessToken(TESTREQUEST1);

        assertThat(tokenService.revokeRefreshToken(token.getAccessToken())).isFalse();

    }


}
