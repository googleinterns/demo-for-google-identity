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
import com.google.common.base.Preconditions;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Singleton
public class ChangePasswordServlet extends HttpServlet {

  private static final long serialVersionUID = 16L;

  private static final Logger log = Logger.getLogger("ChangePasswordServlet");

  private Configuration configuration;

  private final UserDetailsService userDetailsService;

  @Inject
  public ChangePasswordServlet(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  public void init() throws ServletException {
    Version version = new Version("2.3.30");

    configuration = new Configuration(version);

    configuration.setServletContextForTemplateLoading(getServletContext(), "template");
  }

  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    try {
      displayPage(request, response);
    } catch (TemplateException e) {
      log.log(Level.INFO, "Error when display change password page", e);
    }
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    String password = request.getParameter("password");

    UserDetails user = OAuth2Utils.getUserSession(request).getUser().get();

    userDetailsService.updateUser(UserDetails.newBuilder(user).setPassword(password).build());

    OAuth2Utils.setUserSession(request, new UserSession());

    response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
    response.getWriter().println("/login");
    response.getWriter().flush();
  }

  private void displayPage(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, TemplateException {

    Template template = configuration.getTemplate("ChangePassword.ftl");
    UserSession userSession = OAuth2Utils.getUserSession(request);

    Preconditions.checkArgument(
        userSession.getUser().isPresent(), "User should have been logged in already");

    UserDetails user = userSession.getUser().get();

    Map<String, Object> information = new HashMap<>();

    information.put("username", user.getUsername());

    response.setCharacterEncoding("utf-8");
    PrintWriter printWriter = response.getWriter();

    template.process(information, printWriter);

    printWriter.flush();
  }
}
