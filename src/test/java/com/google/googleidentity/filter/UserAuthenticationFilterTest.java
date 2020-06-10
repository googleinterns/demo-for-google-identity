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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.googleidentity.security.UserSession;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

import com.google.inject.Provider;

import com.google.inject.util.Providers;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;


import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

/**
 * Test {@link UserAuthenticationFilter}'s logic
 */
public class UserAuthenticationFilterTest {

    private UserSession session= new UserSession();

    @Test
    public void testFilter_noUserPresent_redirectAndSetOldUrl()
            throws ServletException, IOException {


        UserAuthenticationFilter userAuthenticationFilter = new UserAuthenticationFilter();

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession httpSession = mock(HttpSession.class);
        Map<String, Object> sessionMap = new HashMap<>();

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
        when(request.getRequestURI()).thenReturn("/resource/user");
        when(request.getQueryString()).thenReturn(null);

        userAuthenticationFilter.doFilter(request, response, null);

        verify(response).sendRedirect("/login");

        assertEquals(
                ((UserSession)request.getSession().getAttribute("user_session")).getOlduri().get(),
                "/resource/user");

    }

}

