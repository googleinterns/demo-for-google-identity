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

import com.google.googleidentity.user.UserDetails;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Singleton
public final class LoginCheckServlet extends HttpServlet {

    private static final long serialVersionUID = 4L;

    @Inject
    private Provider<UserSession> session = null;

    @Inject
    public LoginCheckServlet(Provider<UserSession> session){
        this.session = session;
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if(check(username, password)) {
            UserSession usersession = session.get();

            UserDetails.User user =
                    UserDetails.User.newBuilder()
                            .setUsername(username)
                            .setPassword(password)
                            .build();

            usersession.setUser(user);

            if(usersession.getOlduri().equals("")){
                response.getWriter().println("http://" + request.getServerName() + ":"
                        + request.getServerPort() + "/resource/user");
                response.getWriter().flush();
                return;
            }
            else{
                response.getWriter().println("http://" + request.getServerName() + ":"
                        + request.getServerPort() + usersession.getOlduri());
            }

        }
        else{
            response.getWriter().println("http://" + request.getServerName() + ":"
                    + request.getServerPort() + "/login");
        }

    }

    private boolean check(String username, String password){
        return true;
    }


}