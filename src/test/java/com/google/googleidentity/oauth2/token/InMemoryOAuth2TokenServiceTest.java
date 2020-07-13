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
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.ResponseType;
import org.junit.Test;

import java.util.Optional;
import java.util.UUID;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

/** Tests for {@link InMemoryOAuth2TokenService} */
public class InMemoryOAuth2TokenServiceTest {

  private static final String CLIENTID = "client";
  private static final String SECRET = "111";
  private static final String REDIRECT_URI = "http://www.google.com";

  private static final ClientDetails CLIENT =
      ClientDetails.newBuilder()
          .setClientId(CLIENTID)
          .setSecret(Hashing.sha256().hashString(SECRET, Charsets.UTF_8).toString())
          .addScopes("read")
          .setIsScoped(true)
          .addRedirectUris(REDIRECT_URI)
          .addGrantTypes(GrantType.AUTHORIZATION_CODE)
          .build();

  private static final String USERNAME = "111";

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
                  .setResponseType(ResponseType.TOKEN)
                  .setRefreshable(true)
                  .setGrantType(GrantType.AUTHORIZATION_CODE)
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
                  .setResponseType(ResponseType.TOKEN)
                  .setRefreshable(false)
                  .setGrantType(GrantType.IMPLICIT)
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
            .build();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);

    assertThat(token).comparingExpectedFieldsOnly().isEqualTo(expectedAccessToken);
  }

  @Test
  public void testGenerateAccessToken_notRefreshable_noRefreshToken() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST1);

    assertThat(token.getRefreshToken()).isEmpty();
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

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);
    Optional<OAuth2AccessToken> token1 = tokenService.refreshToken(token.getRefreshToken());

    assertThat(token1).isPresent();

    // Ignore access_token value and expired_time
    assertThat(token).ignoringFields(1, 6).isEqualTo(token1.get());
  }

  @Test
  public void testReadAccessToken_correctInput_returnCorrectToken() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);
    Optional<OAuth2AccessToken> token1 = tokenService.readAccessToken(token.getAccessToken());

    assertThat(token1).isPresent();

    assertThat(token).isEqualTo(token1.get());
  }

  @Test
  public void testReadAccessToken_nonExistToken_returnEmpty() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    Optional<OAuth2AccessToken> token = tokenService.readAccessToken(UUID.randomUUID().toString());

    assertThat(token).isEmpty();
  }

  @Test
  public void testReadAccessToken_invalidToken_returnCorrectToken() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);
    Optional<OAuth2AccessToken> token1 = tokenService.readAccessToken(token.getRefreshToken());

    assertThat(token1).isEmpty();
  }

  @Test
  public void testReadRefreshToken_correctInput_returnCorrectToken() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);
    Optional<OAuth2RefreshToken> token1 = tokenService.readRefreshToken(token.getRefreshToken());

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

    Optional<OAuth2RefreshToken> token1 = tokenService.readRefreshToken(token.getAccessToken());

    assertThat(token1).isEmpty();
  }

  @Test
  public void testReadRefreshToken_invalidToken_returnCorrectToken() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    Optional<OAuth2AccessToken> token = tokenService.readAccessToken(UUID.randomUUID().toString());

    assertThat(token).isEmpty();
  }

  @Test
  public void testListUserClient_correctInput_returnCorrectResult() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    tokenService.generateAccessToken(TESTREQUEST0);

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

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);

    assertThat(tokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).containsExactly(token);
  }

  @Test
  public void testListUserClientAccessTokens_userLinkNoClient_returnEmpty() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    assertThat(tokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).isEmpty();
  }

  @Test
  public void testRevokeByAccessToken_correctInput_returnTrueAndRemoveTokens() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);

    assertThat(tokenService.revokeByAccessToken(token.getAccessToken())).isTrue();

    assertThat(tokenService.readAccessToken(token.getAccessToken())).isEmpty();

    assertThat(tokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).isEmpty();

    assertThat(tokenService.getUserClientRefreshToken(USERNAME, CLIENTID)).isEmpty();
  }

  @Test
  public void testRevokeByAccessToken_wrongOrInvalidAccessToken_returnFalse() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    assertThat(tokenService.revokeByAccessToken(UUID.randomUUID().toString())).isFalse();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);

    assertThat(tokenService.revokeByAccessToken(token.getRefreshToken())).isFalse();
  }

  @Test
  public void testRevokeByRefreshToken_correctInput_returnTrueAndRemoveTokens() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST0);

    assertThat(tokenService.revokeByRefreshToken(token.getRefreshToken())).isTrue();

    assertThat(tokenService.readRefreshToken(token.getRefreshToken())).isEmpty();

    assertThat(tokenService.getUserClientRefreshToken(USERNAME, CLIENTID)).isEmpty();

    assertThat(tokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).isEmpty();
  }

  @Test
  public void testRevokeByRefreshToken_wrongOrInvalidRefreshToken_returnFalse() {
    OAuth2TokenService tokenService = new InMemoryOAuth2TokenService();

    assertThat(tokenService.revokeByRefreshToken(UUID.randomUUID().toString())).isFalse();

    OAuth2AccessToken token = tokenService.generateAccessToken(TESTREQUEST1);

    assertThat(tokenService.revokeByRefreshToken(token.getAccessToken())).isFalse();
  }
}
