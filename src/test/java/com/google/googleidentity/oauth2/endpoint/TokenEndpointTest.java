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
import com.google.common.truth.Truth;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.testtools.FakeHttpSession;
import com.google.googleidentity.user.UserDetails;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


/**
 * Tests for {@link TokenEndpoint}, the request check test have been done in
 * {@link com.google.googleidentity.oauth2.validator.TokenEndpointRequestValidatorTest} and
 * {@link com.google.googleidentity.oauth2.ClientAuthenticationFilterTest}.
 * Here we do not do request check tests.
 */
public class TokenEndpointTest {
    private UserSession userSession;

    private ClientSession clientSession;

    private static final String CLIENTID = "111";
    private static final String SECRET = "111";
    private static final String REDIRECT_URI = "http://www.google.com";

    private static final String LINE = System.lineSeparator();

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI)
                    .addGrantTypes("authorization_code")
                    .addGrantTypes("refresh_token")
                    .addGrantTypes("urn:ietf:params:oauth:grant-type:jwt-bearer")
                    .addGrantTypes("implicit")
                    .build();

    private static final String USERNAME = "111";
    private static final String PASSWORD = "111";

    private static final UserDetails USER =
            UserDetails.newBuilder()
                    .setUsername(USERNAME)
                    .setPassword(Hashing.sha256()
                            .hashString(PASSWORD, Charsets.UTF_8).toString())
                    .build();

    private TokenEndpoint tokenEndpoint = null;

    @Before
    public void init() {
        ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.addClient(CLIENT);
        userSession = new UserSession();
        userSession.setUser(USER);
        clientSession = new ClientSession();
        clientSession.setClient(CLIENT);
        tokenEndpoint = new TokenEndpoint(clientDetailsService);
    }

    @Test
    public void testDoGet_throwInvalidGrantException() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("user_session", userSession);
        httpSession.setAttribute("client_session", clientSession);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        tokenEndpoint.doGet(request, response);

        String expected = OAuth2ExceptionHandler.getResponseBody(
                new InvalidRequestException(
                        InvalidRequestException.ErrorCode.UNSUPPORTED_REQUEST_METHOD))
                .toJSONString();

        Truth.assertThat(stringWriter.toString()).isEqualTo(expected + LINE);
    }

}
