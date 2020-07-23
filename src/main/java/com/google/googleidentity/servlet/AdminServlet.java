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

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.authorizationcode.AuthorizationCodeService;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.googleidentity.user.UserSession;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.HttpStatus;

@Singleton
public final class AdminServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;

  private static final Logger log = Logger.getLogger("UserServlet");
  private static final String TESTCLIENTID = "google";
  private static final String TESTSECRET = "secret";
  private static final ImmutableList<String> TESTSCOPES = ImmutableList.of("read");
  private static final ImmutableList<GrantType> TESTGRANTTYPES =
      ImmutableList.of(
          GrantType.AUTHORIZATION_CODE,
          GrantType.IMPLICIT,
          GrantType.REFRESH_TOKEN,
          GrantType.JWT_ASSERTION);
  private static final String TESTREDIRECTURI = "https://www.google.com";
  private static final String TESTREDIRECTURI1 = "https://oauth-redirect.googleusercontent.com/r";
  private static final String TESTREDIRECTURI2 =
      "https://oauth-redirect-sandbox.googleusercontent.com/r";
  private static final String RISCURI = "https://risc.googleapis.com/v1beta/events:report";
  private static final String RISCAUD = "google_account_linking";
  private static final String TESTUSERNAME0 = "user";
  private static final String TESTUSERPASSWORD0 = "123456";
  private static final String TESTUSERNAME1 = "user1";
  private static final String TESTUSERPASSWORD1 = "12345678";
  private static final String ADMIN = "admin";
  private static final String ADMINPASS = "123456789";
  private final ClientDetailsService clientDetailsService;
  private final UserDetailsService userDetailsService;
  private final OAuth2TokenService oauth2TokenService;
  private final AuthorizationCodeService authorizationCodeService;
  private Configuration configuration;

  @Inject
  public AdminServlet(
      ClientDetailsService clientDetailsService,
      UserDetailsService userDetailsService,
      OAuth2TokenService oauth2TokenService,
      AuthorizationCodeService authorizationCodeService) {
    this.clientDetailsService = clientDetailsService;
    this.userDetailsService = userDetailsService;
    this.oauth2TokenService = oauth2TokenService;
    this.authorizationCodeService = authorizationCodeService;
  }

  public void init() throws ServletException {

    Version version = new Version("2.3.30");
    configuration = new Configuration(version);
    configuration.setServletContextForTemplateLoading(getServletContext(), "template");
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    try {
      displayPage(request, response);
    } catch (TemplateException e) {
      throw new OAuth2ServerException("Display Admin Page Error!", e);
    }
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String reset = request.getParameter("reset");

    UserSession userSession = OAuth2Utils.getUserSession(request);

    if ("true".equals(reset)
        && userSession.getUser().isPresent()
        && userSession.getUser().get().getUsername().equals("admin")) {
      clientDetailsService.reset();
      userDetailsService.reset();
      oauth2TokenService.reset();
      authorizationCodeService.reset();
      ClientDetails client =
          ClientDetails.newBuilder()
              .setClientId(TESTCLIENTID)
              .setSecret(Hashing.sha256().hashString(TESTSECRET, Charsets.UTF_8).toString())
              .addAllScopes(TESTSCOPES)
              .setIsScoped(true)
              .addAllGrantTypes(TESTGRANTTYPES)
              .addRedirectUris(TESTREDIRECTURI)
              .addRedirectUris(TESTREDIRECTURI1)
              .addRedirectUris(TESTREDIRECTURI2)
              .setRiscUri(RISCURI)
              .setRiscAud(RISCAUD)
              .build();
      clientDetailsService.addClient(client);
      UserDetails user =
          UserDetails.newBuilder()
              .setUsername(TESTUSERNAME0)
              .setPassword(
                  Hashing.sha256().hashString(TESTUSERPASSWORD0, Charsets.UTF_8).toString())
              .build();

      userDetailsService.addUser(user);

      UserDetails user1 =
          UserDetails.newBuilder()
              .setUsername(TESTUSERNAME1)
              .setPassword(
                  Hashing.sha256().hashString(TESTUSERPASSWORD1, Charsets.UTF_8).toString())
              .build();
      userDetailsService.addUser(user1);
      UserDetails admin =
          UserDetails.newBuilder()
              .setUsername(ADMIN)
              .setPassword(Hashing.sha256().hashString(ADMINPASS, Charsets.UTF_8).toString())
              .build();
      userDetailsService.addUser(admin);
      OAuth2Utils.setUserSession(request, new UserSession());
      response.setStatus(HttpStatus.SC_OK);
      response.getWriter().println("/login");
    } else {
      response.setStatus(HttpStatus.SC_BAD_REQUEST);
      response.getWriter().println("/resource/admin");
    }

  }

  private void displayPage(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, TemplateException {

    UserSession userSession = OAuth2Utils.getUserSession(request);

    Preconditions.checkArgument(
        userSession.getUser().isPresent(), "Admin should have been logged in already");

    if (!userSession.getUser().get().getUsername().equals("admin")) {
      return;
    }

    UserDetails user = userSession.getUser().get();

    Map<String, Object> information = new HashMap<>();

    information.put("username", user.getUsername());

    Template template = configuration.getTemplate("AdminPage.ftl");

    response.setCharacterEncoding("utf-8");
    PrintWriter printWriter = response.getWriter();

    template.process(information, printWriter);

    printWriter.flush();
  }
}
