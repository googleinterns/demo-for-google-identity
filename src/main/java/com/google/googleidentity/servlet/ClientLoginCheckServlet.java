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
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserSession;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Singleton
public class ClientLoginCheckServlet extends HttpServlet {

  private static final long serialVersionUID = 4L;

  private final ClientDetailsService clientDetailsService;

  @Inject
  public ClientLoginCheckServlet(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String clientID = request.getParameter("client_id");
    String secret = request.getParameter("secret");

    response.setContentType("text/html;charset=utf-8");

    if (check(clientID, secret)) {
      UserSession userSession = OAuth2Utils.getUserSession(request);

      userSession.setClient(clientDetailsService.getClientByID(clientID).get());

      OAuth2Utils.setUserSession(request, userSession);
      response.setStatus(HttpStatusCodes.STATUS_CODE_OK);
      response.getWriter().println(userSession.getOlduri().orElse("/client"));

    } else {
      response.setStatus(HttpStatusCodes.STATUS_CODE_UNAUTHORIZED);
      response.getWriter().println("/login");
    }

    response.getWriter().flush();
  }

  private boolean check(String clientID, String secret) {
    Optional<ClientDetails> client = clientDetailsService.getClientByID(clientID);

    return client.isPresent() && Objects.equals(secret, client.get().getSecret());
  }
}
