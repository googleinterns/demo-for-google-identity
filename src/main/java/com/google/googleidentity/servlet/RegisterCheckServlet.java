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

package com.google.googleidentity.servlet;

import com.google.appengine.repackaged.com.google.api.client.http.HttpStatusCodes;
import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// User register check page
@Singleton
public class RegisterCheckServlet extends HttpServlet {

  private static final long serialVersionUID = 14L;

  private final UserDetailsService userDetailsService;

  @Inject
  public RegisterCheckServlet(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String email = request.getParameter("email");

    if (Strings.isNullOrEmpty(username)
        || Strings.isNullOrEmpty(password)
        || Strings.isNullOrEmpty(email)) {
      // This will not happen from the front end interface.
      // Just avoid direct request error.
      return;
    }

    response.setContentType("text/html;charset=utf-8");

    if (userDetailsService.getUserByName(username).isPresent()
        || userDetailsService.getUserByEmailOrGoogleAccountId(email, null).isPresent()) {
      response.setStatus(HttpStatusCodes.STATUS_CODE_UNAUTHORIZED);
    } else {
      userDetailsService.addUser(
          UserDetails.newBuilder()
              .setUsername(username)
              .setPassword(password)
              .setEmail(email)
              .build());

      response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
    }
    response.getWriter().println("/login");
    response.getWriter().flush();
  }
}
