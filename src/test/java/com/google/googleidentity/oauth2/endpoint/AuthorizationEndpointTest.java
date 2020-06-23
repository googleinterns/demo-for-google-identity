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
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.testtools.FakeHttpSession;
import com.google.googleidentity.user.UserDetails;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;


/**
 * Tests for {@link AuthorizationEndpoint}, the request check test have been done in
 * {@link com.google.googleidentity.oauth2.validator.AuthorizationEndpointRequestValidatorTest}.
 * Here we do not do request check tests.
 */
public class AuthorizationEndpointTest {

    private UserSession userSession;

    private ClientSession clientSession;

    private ClientDetailsService clientDetailsService;

    private static final String LINE = System.lineSeparator();

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

    private AuthorizationEndpoint authorizationEndpoint = null;

    @Before
    public void init(){
        clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.addClient(CLIENT);
        userSession = new UserSession();
        userSession.setUser(USER);
        clientSession = new ClientSession();
        authorizationEndpoint = new AuthorizationEndpoint(clientDetailsService);
    }


    @Test
    public void testAuthorizationEndpointGet_EmptyScope_DefaultAsClient()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("user_session", userSession);

        when(request.getSession()).thenReturn(httpSession);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        assertThat(httpSession.getClientSession().getRequest()).isPresent();

        assertThat(
                httpSession.getClientSession()
                        .getRequest().get().getRequestBody().getScopesList())
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

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        verify(response).sendRedirect("/oauth2/consent");

        assertThat(httpSession.getClientSession().getRequest()).isPresent();

        OAuth2Request oauth2Request = httpSession.getClientSession().getRequest().get();

        OAuth2Request.RequestAuth requestAuth = oauth2Request.getRequestAuth();
        assertThat(requestAuth.getClientId()).isEqualTo(CLIENTID);
        assertThat(requestAuth.getUsername()).isEqualTo(USERNAME);

        OAuth2Request.RequestBody requestBody = oauth2Request.getRequestBody();
        assertThat(requestBody.getGrantType()).isEqualTo("authorization_code");
        assertThat(requestBody.getIsScoped()).isTrue();
        assertThat(requestBody.getRefreshable()).isTrue();
        assertThat(requestBody.getResponseType()).isEqualTo("code");
        assertThat(requestBody.getScopesList()).containsExactlyElementsIn(CLIENT.getScopesList());

        OAuth2Request.AuthorizationResponse authorizationResponse =
                oauth2Request.getAuthorizationResponse();
        assertThat(authorizationResponse.getState()).isEqualTo("111");
        assertThat(authorizationResponse.getRedirectUri()).isEqualTo(REDIRECT_URI);

    }
}
