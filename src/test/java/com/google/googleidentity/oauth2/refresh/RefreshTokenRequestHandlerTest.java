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

package com.google.googleidentity.oauth2.refresh;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.common.truth.Truth8;
import com.google.common.truth.extensions.proto.ProtoTruth;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.InMemoryOAuth2TokenService;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.ResponseType;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Optional;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.junit.Before;
import org.junit.Test;

/** Tests for {@link RefreshTokenRequestHandler} */
public class RefreshTokenRequestHandlerTest {
  private static final String CLIENTID = "client";
  private static final String CLIENTID1 = "client1";
  private static final String SECRET = "secret";
  private static final String REDIRECT_URI = "http://www.google.com";
  private static final String REDIRECT_URI1 = "http://www.facebook.com";
  private static final String LINE = System.lineSeparator();
  private static final ClientDetails CLIENT =
      ClientDetails.newBuilder()
          .setClientId(CLIENTID)
          .setSecret(Hashing.sha256().hashString(SECRET, Charsets.UTF_8).toString())
          .addScopes("read")
          .setIsScoped(true)
          .addRedirectUris(REDIRECT_URI)
          .addGrantTypes(GrantType.AUTHORIZATION_CODE)
          .build();
  private static final String USERNAME = "username";
  private static final String PASSWORD = "password";
  private static final String STATE = "state";
  private static final UserDetails USER =
      UserDetails.newBuilder()
          .setUsername(USERNAME)
          .setPassword(Hashing.sha256().hashString(PASSWORD, Charsets.UTF_8).toString())
          .build();
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
          .setAuthorizationResponse(
              OAuth2Request.AuthorizationResponse.newBuilder()
                  .setState(STATE)
                  .setRedirectUri(REDIRECT_URI)
                  .build())
          .build();
  private static final OAuth2Request TEST_REQUEST1 =
      OAuth2Request.newBuilder()
          .setRequestAuth(
              OAuth2Request.RequestAuth.newBuilder()
                  .setClientId(CLIENTID)
                  .setUsername(USERNAME)
                  .build())
          .setRequestBody(
              OAuth2Request.RequestBody.newBuilder()
                  .setResponseType(ResponseType.TOKEN)
                  .setGrantType(GrantType.REFRESH_TOKEN)
                  .build())
          .build();
  RefreshTokenRequestHandler refreshTokenRequestHandler;
  OAuth2TokenService oauth2TokenService;

  @Before
  public void init() {
    oauth2TokenService = new InMemoryOAuth2TokenService();
    refreshTokenRequestHandler = new RefreshTokenRequestHandler(oauth2TokenService);
  }

  @Test
  public void testHandle_NonExistentRefreshToken_throwInvalidGrantException() throws IOException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
    builder.getRequestBodyBuilder().setRefreshToken("non-existent");
    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class,
            () -> refreshTokenRequestHandler.handle(response, builder.build()));

    assertThat(e).isInstanceOf(InvalidGrantException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Refresh token does not exist!");
  }

  @Test
  public void testHandle_wrongClientID_throwInvalidGrantException() throws IOException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    OAuth2AccessToken accessToken = oauth2TokenService.generateAccessToken(TEST_REQUEST);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
    builder.getRequestBodyBuilder().setRefreshToken(accessToken.getRefreshToken());
    builder.getRequestAuthBuilder().setClientId("wrong");
    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class,
            () -> refreshTokenRequestHandler.handle(response, builder.build()));

    assertThat(e).isInstanceOf(InvalidGrantException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Refresh token and client mismatch!");
  }

  @Test
  public void testHandle_correctRequest_returnNewToken() throws IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    OAuth2AccessToken accessToken = oauth2TokenService.generateAccessToken(TEST_REQUEST);

    OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
    builder.getRequestBodyBuilder().setRefreshToken(accessToken.getRefreshToken());
    assertDoesNotThrow(() -> refreshTokenRequestHandler.handle(response, builder.build()));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    assertThat(json).containsKey(OAuth2ParameterNames.ACCESS_TOKEN);
    assertThat(json).containsKey("expires_in");
    assertThat(json).containsEntry("token_type", "Bearer");

    String accessTokenString = json.getAsString(OAuth2ParameterNames.ACCESS_TOKEN);

    OAuth2AccessToken expectedAccessToken =
        OAuth2AccessToken.newBuilder()
            .setAccessToken(accessTokenString)
            .setRefreshToken(accessToken.getRefreshToken())
            .setIsScoped(true)
            .addAllScopes(CLIENT.getScopesList())
            .setClientId(CLIENTID)
            .setUsername(USERNAME)
            .build();
    Optional<OAuth2AccessToken> newAccessToken =
        oauth2TokenService.readAccessToken(accessTokenString);

    Truth8.assertThat(newAccessToken).isPresent();

    ProtoTruth.assertThat(newAccessToken.get())
        .comparingExpectedFieldsOnly()
        .isEqualTo(expectedAccessToken);
  }
}
