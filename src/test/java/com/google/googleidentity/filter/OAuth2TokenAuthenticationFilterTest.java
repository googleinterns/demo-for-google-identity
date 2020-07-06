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

package com.google.googleidentity.filter;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.InMemoryOAuth2TokenService;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.testtools.FakeHttpSession;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

import static com.google.common.truth.Truth8.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2TokenAuthenticationFilter}
 */
public class OAuth2TokenAuthenticationFilterTest {

    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String STATE = "state";

    private static final UserDetails USER =
            UserDetails.newBuilder()
                    .setUsername(USERNAME)
                    .setPassword(Hashing.sha256()
                            .hashString(PASSWORD, Charsets.UTF_8).toString())
                    .build();


    private static final String CLIENTID = "client";
    private static final String SECRET = "secret";
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
                    .addGrantTypes(OAuth2Constants.GrantType.AUTHORIZATION_CODE)
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
                                    .setResponseType(OAuth2Constants.ResponseType.TOKEN)
                                    .setRefreshable(true)
                                    .setGrantType(OAuth2Constants.GrantType.AUTHORIZATION_CODE)
                                    .build())
                    .build();


    @Test
    public void testFilter_noUserPresent_redirectAndSetOldUrl()
            throws ServletException, IOException {

        OAuth2TokenService oauth2TokenService = new InMemoryOAuth2TokenService();

        UserDetailsService userDetailsService = new InMemoryUserDetailsService();

        userDetailsService.addUser(USER);

        OAuth2TokenAuthenticationFilter oauth2TokenAuthenticationFilter
                = new OAuth2TokenAuthenticationFilter(
                        userDetailsService,
                        oauth2TokenService);

        OAuth2AccessToken token = oauth2TokenService.generateAccessToken(TESTREQUEST0);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        when(request.getSession()).thenReturn(httpSession);
        when(request.getParameter(OAuth2ParameterNames.ACCESS_TOKEN))
                .thenReturn(token.getAccessToken());

        oauth2TokenAuthenticationFilter.doFilter(request, response, chain);

        assertThat(httpSession.getUserSession().getUser()).hasValue(USER);

    }
}
