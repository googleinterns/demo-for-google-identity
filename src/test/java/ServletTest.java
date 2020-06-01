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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.logging.Logger;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.filter.UserAuthenticationFilter;
import com.google.googleidentity.security.LoginCheckServlet;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Injector;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import com.google.inject.Provider;

import org.junit.Before;
import org.junit.Test;


import static org.mockito.Mockito.*;

public class ServletTest  {

    private Injector injector;

    @Before
    public void setUp(){
    }

    public class UserSessionProvider implements Provider<UserSession> {
        @Override
        public UserSession get() {
            UserSession userSession = new UserSession();
            userSession.setUser(UserDetails.newBuilder()
                    .setUsername("user")
                    .setPassword(Hashing.sha256()
                            .hashString("123456", Charsets.UTF_8).toString())
                    .build());
            return userSession;
        }
    }

    private UserSession session= new UserSession();

    public class UserSessionProvider1 implements Provider<UserSession> {
        @Override
        public UserSession get() {
            return session;
        }
    }

    /**
     * Test logincheckservelet's logic
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testLoginCheckServlet() throws ServletException, IOException {

        UserDetailsService userDetailsService = new InMemoryUserDetailsService();

        userDetailsService.addUser(UserDetails.newBuilder()
                .setUsername("user")
                .setPassword(Hashing.sha256()
                        .hashString("123456", Charsets.UTF_8).toString())
                .build());

        LoginCheckServlet loginCheckServlet = new LoginCheckServlet(
                new UserSessionProvider(), userDetailsService);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getParameter("username")).thenReturn("user");
        when(request.getParameter("password")).thenReturn(Hashing.sha256()
                .hashString("12345", Charsets.UTF_8).toString());

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        loginCheckServlet.doPost(request, response);

        assertTrue(stringWriter.toString().startsWith("/login"));

        when(request.getParameter("password")).thenReturn(Hashing.sha256()
                .hashString("123456", Charsets.UTF_8).toString());

        stringWriter = new StringWriter();
        writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        loginCheckServlet.doPost(request, response);

        assertTrue(stringWriter.toString().startsWith("/resource/user"));

    }

    /**
     * Test UserAuthenticationFilter's logic
     *
     * @throws ServletException
     * @throws IOException
     */
    @Test
    public void testUserAuthenticationFilter() throws ServletException, IOException {

        Provider<UserSession> userSessionProvider = new UserSessionProvider1();

        UserAuthenticationFilter userAuthenticationFilter = new UserAuthenticationFilter(
                userSessionProvider);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getRequestURI()).thenReturn("/resource/user");
        when(request.getQueryString()).thenReturn(null);

        userAuthenticationFilter.doFilter(request, response, null);


        assertTrue(userSessionProvider.get().getOlduri().isPresent());

    }




}

