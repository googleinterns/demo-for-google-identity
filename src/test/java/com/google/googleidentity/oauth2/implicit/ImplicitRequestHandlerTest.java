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

package com.google.googleidentity.oauth2.implicit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.refresh.RefreshTokenRequestHandler;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.InMemoryOAuth2TokenService;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.ResponseType;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import java.io.IOException;
import java.util.List;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;

public class ImplicitRequestHandlerTest {
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
                  .setGrantType(GrantType.IMPLICIT)
                  .build())
          .setAuthorizationResponse(
              OAuth2Request.AuthorizationResponse.newBuilder()
                  .setState(STATE)
                  .setRedirectUri(REDIRECT_URI)
                  .build())
          .build();
  ImplicitRequestHandler implicitRequestHandler;
  OAuth2TokenService oauth2TokenService;

  @Before
  public void init() {
    oauth2TokenService = new InMemoryOAuth2TokenService();
    implicitRequestHandler = new ImplicitRequestHandler(oauth2TokenService);
  }

  @Test
  public void testHandleCodeRequest_correctRequest_redirect() throws IOException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    assertDoesNotThrow(() -> implicitRequestHandler.handle(response, TEST_REQUEST));

    List<OAuth2AccessToken> list =
        oauth2TokenService.listUserClientAccessTokens(USERNAME, CLIENTID);

    verify(response)
        .sendRedirect(
            REDIRECT_URI
                + "?access_token="
                + list.get(0).getAccessToken()
                + "&token_type=bearer&state="
                + STATE);
  }
}
