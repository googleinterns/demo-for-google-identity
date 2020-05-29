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

import com.google.appengine.repackaged.com.google.api.client.http.HttpStatusCodes;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * Demo Login Check Servlet
 * Check the username and password in the post request, return the redirect link.
 * For a success login request, a UserDetails.User Object
 * {@link com.google.googleidentity.user.UserDetails} will
 * be stored in the session through class
 * {@link com.google.googleidentity.security.UserSession}.
 * The redirect link for a success request is to the original request
 * or the default as /resource/user.
 * The redirect link for a failed request is still the login page.
 */
@Singleton
public final class LoginCheckServlet extends HttpServlet {

    private static final long serialVersionUID = 4L;

    private final Provider<UserSession> session;

    private final UserDetailsService userDetailsService;

    @Inject
    public LoginCheckServlet(Provider<UserSession> session, UserDetailsService userDetailsService) {
        this.session = session;
        this.userDetailsService = userDetailsService;
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        response.setContentType("text/html;charset=utf-8");

        if (check(username, password)) {
            UserSession usersession = session.get();

            UserDetails.User user =
                    UserDetails.User.newBuilder()
                            .setUsername(username)
                            .setPassword(password)
                            .build();

            usersession.setUser(user);

            if (usersession.getOlduri() == null) {
                response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
                response.getWriter().println("http://" + request.getServerName() + ":"
                        + request.getServerPort() + "/resource/user");
            } else {
                response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
                response.getWriter().println("http://" + request.getServerName() + ":"
                        + request.getServerPort() + usersession.getOlduri());
            }

        } else {
            response.setStatus(HttpStatusCodes.STATUS_CODE_UNAUTHORIZED);
            response.getWriter().println("http://" + request.getServerName() + ":"
                    + request.getServerPort() + "/login");
        }

        response.getWriter().flush();
        return;

    }

    private boolean check(String username, String password) {
        UserDetails.User user = userDetailsService.getUserByName(username);

        if (user == null) {
            return false;
        }

        return Objects.equals(password, user.getPassword());
    }


}