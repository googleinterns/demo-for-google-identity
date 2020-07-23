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

package com.google.googleidentity.oauth2.endpoint;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.common.truth.Truth;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.request.RequestHandler;
import com.google.googleidentity.oauth2.token.InMemoryOAuth2TokenService;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.ResponseType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.TokenType;
import com.google.googleidentity.testtools.FakeHttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;

/** Test for {@link TokenRevokeEndpoint} */
public class TokenRevokeEndpointTest {
  private static final String CLIENTID = "client";
  private static final String SECRET = "111";
  private static final String REDIRECT_URI = "http://www.google.com";
  private static final String LINE = System.lineSeparator();
  private static final ImmutableList<GrantType> TESTGRANTTYPES =
      ImmutableList.of(
          GrantType.AUTHORIZATION_CODE,
          GrantType.IMPLICIT,
          GrantType.REFRESH_TOKEN,
          GrantType.JWT_ASSERTION);
  private static final ClientDetails CLIENT =
      ClientDetails.newBuilder()
          .setClientId(CLIENTID)
          .setSecret(Hashing.sha256().hashString(SECRET, Charsets.UTF_8).toString())
          .addScopes("read")
          .setIsScoped(true)
          .addRedirectUris(REDIRECT_URI)
          .addAllGrantTypes(TESTGRANTTYPES)
          .build();
  private static final String USERNAME = "user";
  private static final OAuth2Request TEST_REQUEST =
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
  private ClientSession clientSession;
  private TokenRevokeEndpoint tokenRevokeEndpoint;
  private OAuth2TokenService oauth2TokenService;

  @Before
  public void init() {
    oauth2TokenService = new InMemoryOAuth2TokenService();
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
    clientDetailsService.addClient(CLIENT);
    clientSession = new ClientSession();
    clientSession.setClient(CLIENT);
    Map<GrantType, RequestHandler> map = new HashMap<>();
    tokenRevokeEndpoint = new TokenRevokeEndpoint(clientDetailsService, oauth2TokenService);
  }

  @Test
  public void testDoGet_throwInvalidGrantException() throws IOException, ServletException {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FakeHttpSession httpSession = new FakeHttpSession();
    httpSession.setAttribute("client_session", clientSession);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    tokenRevokeEndpoint.doGet(request, response);

    String expected =
        OAuth2ExceptionHandler.getResponseBody(
                new InvalidRequestException(
                    InvalidRequestException.ErrorCode.UNSUPPORTED_REQUEST_METHOD))
            .toJSONString();

    Truth.assertThat(stringWriter.toString()).isEqualTo(expected + LINE);
  }

  @Test
  public void testRevokeToken_nonexistentToken_NoException() {
    HttpServletResponse response = mock(HttpServletResponse.class);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder();

    builder.getRequestAuthBuilder().setClientId(CLIENTID);

    builder.getRequestBodyBuilder().setTokenTypeHint(TokenType.ACCESS).setTokenToRevoke("token");
    assertDoesNotThrow(() -> tokenRevokeEndpoint.revokeToken(response, builder.build()));
  }

  @Test
  public void testRevokeToken_tokenClientIdMismatch_throwInvalidGrantException() {
    HttpServletResponse response = mock(HttpServletResponse.class);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder();
    OAuth2AccessToken token = oauth2TokenService.generateAccessToken(TEST_REQUEST);

    builder.getRequestAuthBuilder().setClientId(CLIENTID + "1");
    builder
        .getRequestBodyBuilder()
        .setTokenTypeHint(TokenType.ACCESS)
        .setTokenToRevoke(token.getAccessToken());
    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class,
            () -> tokenRevokeEndpoint.revokeToken(response, builder.build()));

    assertThat(e).isInstanceOf(InvalidGrantException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Token to be revoked and client id mismatch!");
  }

  @Test
  public void testRevokeToken_correctRequestByAccessToken_RevokeTokenAndThrowNoException() {
    HttpServletResponse response = mock(HttpServletResponse.class);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder();
    OAuth2AccessToken token = oauth2TokenService.generateAccessToken(TEST_REQUEST);

    builder.getRequestAuthBuilder().setClientId(CLIENTID);
    builder
        .getRequestBodyBuilder()
        .setTokenTypeHint(TokenType.ACCESS)
        .setTokenToRevoke(token.getAccessToken());
    assertDoesNotThrow(() -> tokenRevokeEndpoint.revokeToken(response, builder.build()));

    assertThat(oauth2TokenService.listUserClientRefreshTokens(USERNAME, CLIENTID)).isEmpty();
    assertThat(oauth2TokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).isEmpty();
  }

  @Test
  public void testRevokeToken_correctRequestByRefreshToken_RevokeTokenAndThrowNoException() {
    HttpServletResponse response = mock(HttpServletResponse.class);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder();
    OAuth2AccessToken token = oauth2TokenService.generateAccessToken(TEST_REQUEST);

    builder.getRequestAuthBuilder().setClientId(CLIENTID);
    builder
        .getRequestBodyBuilder()
        .setTokenTypeHint(TokenType.REFRESH)
        .setTokenToRevoke(token.getRefreshToken());
    assertDoesNotThrow(() -> tokenRevokeEndpoint.revokeToken(response, builder.build()));

    assertThat(oauth2TokenService.listUserClientRefreshTokens(USERNAME, CLIENTID)).isEmpty();
    assertThat(oauth2TokenService.listUserClientAccessTokens(USERNAME, CLIENTID)).isEmpty();
  }
}
