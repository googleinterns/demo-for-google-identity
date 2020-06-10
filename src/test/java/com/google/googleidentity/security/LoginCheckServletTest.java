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

package com.google.googleidentity.security;


import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import static com.google.common.truth.Truth.assertThat;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;


import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;



import com.google.inject.Provider;

import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;


import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test {@link LoginCheckServlet}'s logic
 */
public class LoginCheckServletTest  {

    private static final String LINE = System.lineSeparator();

    @Test
    public void testLoginCheckServlet_correctLoginRequest_redirectToResource()
            throws ServletException, IOException {

        UserDetailsService userDetailsService = new InMemoryUserDetailsService();

        userDetailsService.addUser(UserDetails.newBuilder()
                .setUsername("user")
                .setPassword(Hashing.sha256()
                        .hashString("correct password", Charsets.UTF_8).toString())
                .build());

        LoginCheckServlet loginCheckServlet = new LoginCheckServlet(userDetailsService);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put("user_session", new UserSession());

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

        when(request.getParameter("username")).thenReturn("user");
        when(request.getParameter("password")).thenReturn(Hashing.sha256()
                .hashString("correct password", Charsets.UTF_8).toString());

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        loginCheckServlet.doPost(request, response);

        assertThat(stringWriter.toString()).isEqualTo("/resource/user" + LINE);

    }

    @Test
    public void testLoginCheckServlet_wrongLoginRequest_redirectToLogin()
            throws ServletException, IOException {

        UserDetailsService userDetailsService = new InMemoryUserDetailsService();

        userDetailsService.addUser(UserDetails.newBuilder()
                .setUsername("user")
                .setPassword(Hashing.sha256()
                        .hashString("correct password", Charsets.UTF_8).toString())
                .build());

        LoginCheckServlet loginCheckServlet = new LoginCheckServlet(userDetailsService);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> sessionMap = new HashMap<>();

        sessionMap.put("user_session", new UserSession());

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

        when(request.getParameter("username")).thenReturn("user");
        when(request.getParameter("password")).thenReturn(Hashing.sha256()
                .hashString("wrong password", Charsets.UTF_8).toString());

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        loginCheckServlet.doPost(request, response);

        assertThat(stringWriter.toString()).isEqualTo("/login" + LINE);

    }

}

