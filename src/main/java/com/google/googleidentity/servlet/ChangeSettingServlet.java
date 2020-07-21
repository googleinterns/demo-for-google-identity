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
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import com.google.googleidentity.oauth2.util.OAuth2Enums;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserSession;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Singleton
public class ChangeSettingServlet extends HttpServlet {

  private static final long serialVersionUID = 16L;

  private static final Logger log = Logger.getLogger("ChangeSettingServlet");
  private final ClientDetailsService clientDetailsService;
  private Configuration configuration;

  @Inject
  public ChangeSettingServlet(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
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
      log.log(Level.INFO, "Error when display  page", e);
    }
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    String secret = request.getParameter("secret");

    String[] scopes = request.getParameter("scopes").split(";");

    String[] redirectUri = request.getParameter("redirect_uris").split(";");

    String[] grantTypes = request.getParameter("grant_types").split(";");

    String riscUri = request.getParameter("risc_uri");
    String riscAud = request.getParameter("risc_aud");
    ClientDetails client = OAuth2Utils.getUserSession(request).getClient().get();

    Set<GrantType> set = new HashSet<>();

    for (String grantType : grantTypes) {
      if (!OAuth2EnumMap.GRANT_TYPE_MAP.containsKey(grantType)) {
        response.setStatus(HttpStatusCodes.STATUS_CODE_BAD_REQUEST);
        response.getWriter().println("/client");
        response.getWriter().flush();
      }
      set.add(OAuth2EnumMap.GRANT_TYPE_MAP.get(grantType));
    }

    ClientDetails.Builder builder = ClientDetails.newBuilder(client);
    builder.setSecret(secret);
    builder.clearGrantTypes().addAllGrantTypes(set);
    builder.setIsScoped(scopes.length == 0);
    builder.clearScopes().addAllScopes(ImmutableList.copyOf(scopes));
    builder.clearRedirectUris().addAllRedirectUris(ImmutableList.copyOf(redirectUri));
    builder.setRiscAud(riscAud);
    builder.setRiscUri(riscUri);

    clientDetailsService.updateClient(builder.build());

    OAuth2Utils.setUserSession(request, new UserSession());

    response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
    response.getWriter().println("/login");
    response.getWriter().flush();
  }

  private void displayPage(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, TemplateException {

    Template template = configuration.getTemplate("ChangeSetting.ftl");
    UserSession userSession = OAuth2Utils.getUserSession(request);

    Preconditions.checkArgument(
        userSession.getClient().isPresent(), "Client should have been logged in already");

    ClientDetails client = userSession.getClient().get();

    Map<String, Object> information = new HashMap<>();

    information.put("clientID", client.getClientId());
    information.put("secret", client.getSecret());
    List<String> grantTypes = new ArrayList<>();

    for (OAuth2Enums.GrantType type : client.getGrantTypesList()) {
      grantTypes.add(OAuth2EnumMap.REVERSE_GRANT_TYPE_MAP.get(type));
    }
    information.put("grant_types", String.join(";", grantTypes));
    information.put("scopes", String.join(";", client.getScopesList()));
    information.put("redirect_uris", String.join(";", client.getRedirectUrisList()));
    information.put("risc_uri", client.getRiscUri());
    information.put("risc_aud", client.getRiscAud());

    response.setCharacterEncoding("utf-8");
    PrintWriter printWriter = response.getWriter();

    template.process(information, printWriter);

    printWriter.flush();
  }
}
