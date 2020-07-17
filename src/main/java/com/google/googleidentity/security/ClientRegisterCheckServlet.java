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
import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// User register check page
@Singleton
public class ClientRegisterCheckServlet extends HttpServlet {

  private static final long serialVersionUID = 14L;

  private final ClientDetailsService clientDetailsService;

  @Inject
  public ClientRegisterCheckServlet(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String clientID = request.getParameter("client_id");

    if (clientDetailsService.getClientByID(clientID).isPresent()) {
      response.setStatus(HttpStatusCodes.STATUS_CODE_BAD_REQUEST);
      response.getWriter().println("/register");
      response.getWriter().flush();
    }

    String secret = request.getParameter("secret");

    String[] scopes = request.getParameter("scopes").split(";");

    String[] redirectUri = request.getParameter("redirect_uris").split(";");

    String[] grantTypes = request.getParameter("grant_types").split(";");

    String riscUri = request.getParameter("risc_uri");
    String riscAud = request.getParameter("risc_aud");

    Set<GrantType> set = new HashSet<>();

    for (String grantType : grantTypes) {
      if (!OAuth2EnumMap.GRANT_TYPE_MAP.containsKey(grantType)) {
        response.setStatus(HttpStatusCodes.STATUS_CODE_BAD_REQUEST);
        response.getWriter().println("/register_client");
        response.getWriter().flush();
      }
      set.add(OAuth2EnumMap.GRANT_TYPE_MAP.get(grantType));
    }

    ClientDetails.Builder builder = ClientDetails.newBuilder();
    builder.setClientId(clientID);
    builder.setSecret(secret);
    builder.clearGrantTypes().addAllGrantTypes(set);
    builder.setIsScoped(scopes.length == 0);
    builder.clearScopes().addAllScopes(ImmutableList.copyOf(scopes));
    builder.clearRedirectUris().addAllRedirectUris(ImmutableList.copyOf(redirectUri));
    builder.setRiscAud(riscAud);
    builder.setRiscUri(riscUri);

    clientDetailsService.addClient(builder.build());
    response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
    response.getWriter().println("/login");
    response.getWriter().flush();
  }

}
