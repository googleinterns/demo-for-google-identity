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
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.security.LoginCheckServlet;
import com.google.googleidentity.security.LoginCheckServletTest;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.util.Providers;
import net.minidev.json.JSONObject;
import org.apache.http.HttpStatus;
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
import static org.mockito.Mockito.*;


/**
 * Tests for {@link AuthorizationEndpoint}
 */
public class AuthorizationEndpointTest {

    private UserSession userSession;

    private ClientSession clientSession;

    private ClientDetailsService clientDetailsService;

    private static final String LINE = System.lineSeparator();

    private static final String CLIENTID = "111";
    private static final String SECRET = "111";
    private static final String REDIRECT_URI = "http://localhost:8080/redirect";

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI)
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
    public void testAuthorizationEndpoint_NoOrWrongResponseType_Error()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","No Response Type!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

        response = mock(HttpServletResponse.class);

        stringWriter = new StringWriter();
        writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("wrong_type");

        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        json.appendField("info","Invalid Response Type!");

        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);
    }

    @Test
    public void testAuthorizationEndpoint_NoOrWrongClientID_Error()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","No clientID!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

        response = mock(HttpServletResponse.class);

        stringWriter = new StringWriter();
        writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("wrong_client");

        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        json.appendField("info","Invalid clientID!");

        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);
    }

    @Test
    public void testAuthorizationEndpoint_NoOrWrongRedirectUri_Error()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","No Redirect URI!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

        response = mock(HttpServletResponse.class);

        stringWriter = new StringWriter();
        writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn("wrong_uri");

        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        json.appendField("info","Redirect URI Mismatch!");

        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);
    }

    @Test
    public void testAuthorizationEndpoint_WrongScope_Error()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("wrong_scope");

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","Scope Not Support!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

    }

    @Test
    public void testAuthorizationEndpoint_EmptyScope_DefaultAsClient()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put("user_session", userSession);

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                return sessionMap.get(key);
            }
        }).when(httpSession).getAttribute(anyString());

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                Object value = invocationOnMock.getArguments()[1];
                sessionMap.put(key, value);
                return null;
            }
        }).when(httpSession).setAttribute(anyString(), anyObject());

        when(request.getSession()).thenReturn(httpSession);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("code");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doGet(request, response);

        assertThat(
                ((ClientSession) request.getSession().getAttribute("client_session"))
                        .getRequest().get().getRequestBody().getScopesList())
                .isEqualTo(CLIENT.getScopesList());

    }

    @Test
    public void testAuthorizationEndpoint_CorrectRequest_RedirectToApprovalAndCorrectRequest()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put("user_session", userSession);

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                return sessionMap.get(key);
            }
        }).when(httpSession).getAttribute(anyString());

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                Object value = invocationOnMock.getArguments()[1];
                sessionMap.put(key, value);
                return null;
            }
        }).when(httpSession).setAttribute(anyString(), anyObject());

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

        verify(response).sendRedirect("/oauth2/approval");

        assertThat(
                ((ClientSession) request.getSession().getAttribute("client_session"))
                        .getRequest().get())
                .isEqualTo(
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
                                                .setResponseType("code")
                                                .setRefreshable(true)
                                                .setGrantType("authorization_code")
                                                .build())
                                .setAuthorizationResponse(
                                        OAuth2Request.AuthorizationResponse.newBuilder()
                                                .setState("111")
                                                .setRedirectUri(REDIRECT_URI)
                                                .build())
                                .build());

    }


    @Test
    public void testAuthorizationEndpoint_PostRequestWithOutApproval_RedirectToGet()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(null);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doPost(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","No Response Type!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

    }


    @Test
    public void testAuthorizationEndpoint_UserDeny_Error()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter("user_deny")).thenReturn("true");

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        authorizationEndpoint.doPost(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","User Deny!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

    }


    @Test
    public void testAuthorizationEndpoint_NoRequest_Error()
            throws ServletException, IOException {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put("user_session", userSession);

        clientSession.setRequest(null);

        sessionMap.put("client_session", clientSession);

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                return sessionMap.get(key);
            }
        }).when(httpSession).getAttribute(anyString());

        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String key = (String) invocationOnMock.getArguments()[0];
                Object value = invocationOnMock.getArguments()[1];
                sessionMap.put(key, value);
                return null;
            }
        }).when(httpSession).setAttribute(anyString(), anyObject());

        when(request.getSession()).thenReturn(httpSession);

        when(request.getParameter("user_approval")).thenReturn("true");



        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);


        authorizationEndpoint.doPost(request, response);

        verify(response).setStatus(HttpStatus.SC_BAD_REQUEST);

        JSONObject json = new JSONObject();
        json.appendField("error", "invalid_request");
        json.appendField("info","No OAuth2Request!");
        assertThat(stringWriter.toString())
                .isEqualTo(json.toJSONString() + LINE);

    }



}
