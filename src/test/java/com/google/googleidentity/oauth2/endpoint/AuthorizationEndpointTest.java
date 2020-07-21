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

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.request.RequestHandler;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.ResponseType;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.user.UserSession;
import com.google.googleidentity.testtools.FakeHttpSession;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationEndpoint}, the request check test have been done in {@link
 * com.google.googleidentity.oauth2.validator.AuthorizationEndpointRequestValidatorTest}. Here we do
 * not do request check tests.
 */
public class AuthorizationEndpointTest {

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
  private static final String USERNAME = "usernames";
  private static final String PASSWORD = "password";
  private static final UserDetails USER =
      UserDetails.newBuilder()
          .setUsername(USERNAME)
          .setPassword(Hashing.sha256().hashString(PASSWORD, Charsets.UTF_8).toString())
          .build();
  private UserSession userSession;
  private AuthorizationEndpoint authorizationEndpoint = null;

  @Before
  public void init() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
    clientDetailsService.addClient(CLIENT);
    UserDetailsService userDetailsService = new InMemoryUserDetailsService();
    userDetailsService.addUser(USER);
    userSession = new UserSession();
    userSession.setUser(USER);
    RequestHandler requestHandler = mock(RequestHandler.class);
    authorizationEndpoint =
        new AuthorizationEndpoint(clientDetailsService, requestHandler);
  }

  @Test
  public void testAuthorizationEndpointGet_EmptyScope_DefaultAsClient()
      throws ServletException, IOException {

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FakeHttpSession httpSession = new FakeHttpSession();

    httpSession.setAttribute("user_session", userSession);

    when(request.getSession()).thenReturn(httpSession);

    when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
        .thenReturn(OAuth2Constants.ResponseType.CODE);
    when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
    when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
    when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(null);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    authorizationEndpoint.doGet(request, response);

    assertThat(httpSession.getClientSession().getRequest()).isPresent();

    assertThat(httpSession.getClientSession().getRequest().get().getRequestBody().getScopesList())
        .containsExactlyElementsIn(CLIENT.getScopesList());
  }

  @Test
  public void testAuthorizationEndpointGet_CorrectRequest_RedirectToConsentAndCorrectRequest()
      throws ServletException, IOException {

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FakeHttpSession httpSession = new FakeHttpSession();

    httpSession.setAttribute("user_session", userSession);

    when(request.getSession()).thenReturn(httpSession);

    when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
        .thenReturn(OAuth2Constants.ResponseType.CODE);
    when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
    when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
    when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
    when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    authorizationEndpoint.doGet(request, response);

    verify(response).sendRedirect("/oauth2/consent");

    OAuth2Request exceptedRequest =
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
                    .setResponseType(ResponseType.CODE)
                    .setRefreshable(true)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .build())
            .setAuthorizationResponse(
                OAuth2Request.AuthorizationResponse.newBuilder()
                    .setState("111")
                    .setRedirectUri(REDIRECT_URI)
                    .build())
            .build();

    assertThat(httpSession.getClientSession().getRequest()).isPresent();

    assertThat(httpSession.getClientSession().getRequest().get()).isEqualTo(exceptedRequest);
  }
}
