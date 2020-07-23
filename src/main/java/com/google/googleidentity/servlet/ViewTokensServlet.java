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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserSession;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Singleton
public final class ViewTokensServlet extends HttpServlet {

  private static final long serialVersionUID = 17L;

  private static final Logger log = Logger.getLogger("UnlinkServlet");
  private final OAuth2TokenService oauth2TokenService;
  private Configuration configuration;

  @Inject
  public ViewTokensServlet(OAuth2TokenService oauth2TokenService) {
    this.oauth2TokenService = oauth2TokenService;
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
      log.log(Level.INFO, "display Page Error!", e);
    }
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    try {
      displayPage(request, response);
    } catch (TemplateException e) {
      log.log(Level.INFO, "display Page Error!", e);
    }
  }

  private void displayPage(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, TemplateException {

    UserSession userSession = OAuth2Utils.getUserSession(request);

    Preconditions.checkArgument(
        userSession.getUser().isPresent(), "User should have been logged in already");

    UserDetails user = userSession.getUser().get();

    Map<String, Object> information = new HashMap<>();

    information.put("username", user.getUsername());

    List<List<String>> accessTokenList = new LinkedList<>();
    List<List<String>> refreshTokenList = new LinkedList<>();
    for (String client : oauth2TokenService.listUserClient(user.getUsername())) {
      for (OAuth2AccessToken token :
          oauth2TokenService.listUserClientAccessTokens(user.getUsername(), client)) {
        accessTokenList.add(
            ImmutableList.of(
                token.getAccessToken(),
                token.getClientId(),
                String.valueOf(token.getIsScoped()),
                String.join("\t", token.getScopesList()),
                Instant.ofEpochSecond(token.getExpiredTime()).toString(),
                token.getRefreshToken()));
      }

      for (OAuth2RefreshToken token :
          oauth2TokenService.listUserClientRefreshTokens(user.getUsername(), client)) {
        refreshTokenList.add(
            ImmutableList.of(
                token.getRefreshToken(),
                token.getClientId(),
                String.valueOf(token.getIsScoped()),
                String.join("\t", token.getScopesList())));
      }
    }

    information.put("accessTokens", accessTokenList);
    information.put("refreshTokens", refreshTokenList);

    Template template = configuration.getTemplate("ViewTokens.ftl");

    response.setCharacterEncoding("utf-8");
    PrintWriter printWriter = response.getWriter();

    template.process(information, printWriter);

    printWriter.flush();
  }
}
