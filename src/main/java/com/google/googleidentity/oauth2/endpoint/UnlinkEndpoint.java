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

package com.google.googleidentity.oauth2.endpoint;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.risc.RiscHandler;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * When user request to revoke token with a client , the request will be sent here. In the demo,
 * user can send the request from MainPage. It will check the user session and client id and then
 * send it to {@link RiscHandler}.
 */
@Singleton
public class UnlinkEndpoint extends HttpServlet {

  private static final long serialVersionUID = 12L;

  private static final Logger log = Logger.getLogger("RiscEndpoint");

  private final RiscHandler riscHandler;

  private final ClientDetailsService clientDetailsService;

  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public UnlinkEndpoint(
      RiscHandler riscHandler,
      ClientDetailsService clientDetailsService,
      OAuth2TokenService oauth2TokenService) {
    this.riscHandler = riscHandler;
    this.clientDetailsService = clientDetailsService;
    this.oauth2TokenService = oauth2TokenService;
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    if (OAuth2Utils.getUserSession(request).getUser().isPresent()) {
      String clientID = request.getParameter("client");
      String username = OAuth2Utils.getUserSession(request).getUser().get().getUsername();

      if (!Strings.isNullOrEmpty(clientID)
          && clientDetailsService.getClientByID(clientID).isPresent()) {
        Optional<ClientDetails> client = clientDetailsService.getClientByID(clientID);

        List<OAuth2AccessToken> accessTokenList =
            oauth2TokenService.listUserClientAccessTokens(username, clientID);

        Optional<OAuth2RefreshToken> refreshToken =
            oauth2TokenService.getUserClientRefreshToken(username, clientID);

        oauth2TokenService.revokeUserClientTokens(username, clientID);

        if (!Strings.isNullOrEmpty(client.get().getRiscUri())) {
          riscHandler.SendRisc(accessTokenList, refreshToken);
        }
      }
    }
    response.sendRedirect("/resource/user");
  }
}
