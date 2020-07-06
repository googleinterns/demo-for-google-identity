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

package com.google.googleidentity.oauth2;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;

import com.google.googleidentity.oauth2.exception.InvalidClientException;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.filter.ClientAuthenticationFilter;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.testtools.FakeHttpSession;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

public class ClientAuthenticationFilterTest {

    private static final String LINE = System.lineSeparator();

    private static final String CLIENTID = "google";
    private static final String SECRET = "secret";

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .build();

    ClientAuthenticationFilter clientAuthenticationFilter;

    @Before
    public void init(){
        ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.addClient(CLIENT);
        clientAuthenticationFilter = new ClientAuthenticationFilter(clientDetailsService);
    }


    @Test
    public void testFilter_noGrantType_throwInvalidGrantException()
            throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        when(request.getSession()).thenReturn(httpSession);
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        clientAuthenticationFilter.doFilter(request, response, chain);

        String expected = OAuth2ExceptionHandler.getResponseBody(
                new InvalidGrantException(InvalidGrantException.ErrorCode.NO_GRANT_TYPE))
                .toJSONString();

        assertThat(stringWriter.toString()).isEqualTo(expected + LINE);
    }

    @Test
    public void testFilter_Jwt_SetCleintToGoogle()
            throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        when(request.getSession()).thenReturn(httpSession);
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn("urn:ietf:params:oauth:grant-type:jwt-bearer");

        clientAuthenticationFilter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);

        assertThat(httpSession.getClientSession().getClient()).hasValue(CLIENT);

    }

    @Test
    public void testFilter_NoClientID_throwInvalidRequestException()
            throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        when(request.getSession()).thenReturn(httpSession);
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn("authorization_code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        clientAuthenticationFilter.doFilter(request, response, chain);

        String expected = OAuth2ExceptionHandler.getResponseBody(
                new InvalidRequestException(InvalidRequestException.ErrorCode.NO_CLIENT_ID))
                .toJSONString();

        assertThat(stringWriter.toString()).isEqualTo(expected + LINE);
    }

    @Test
    public void testFilter_wrongSecret_throwInvalidClientException()
            throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        when(request.getSession()).thenReturn(httpSession);
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn("authorization_code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET)).thenReturn("wrong");

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        clientAuthenticationFilter.doFilter(request, response, chain);

        String expected = OAuth2ExceptionHandler.getResponseBody(
                new InvalidClientException())
                .toJSONString();

        assertThat(stringWriter.toString()).isEqualTo(expected + LINE);
    }


    @Test
    public void testFilter_Correct_doFilterToNextPage()
            throws ServletException, IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        when(request.getSession()).thenReturn(httpSession);
        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn("authorization_code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET)).thenReturn(SECRET);

        clientAuthenticationFilter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);

        assertThat(httpSession.getClientSession().getClient()).hasValue(CLIENT);

    }


}
