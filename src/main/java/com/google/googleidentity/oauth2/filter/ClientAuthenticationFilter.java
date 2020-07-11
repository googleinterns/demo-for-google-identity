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

package com.google.googleidentity.oauth2.filter;

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.exception.*;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Optional;
import java.util.logging.Logger;

/** The filter to protect oauth2 resources using clientid and secret */
@Singleton
public final class ClientAuthenticationFilter implements Filter {
  private static final Logger log = Logger.getLogger("ClientAuthenticationFilter");
  private static final String GOOGLE_CLIENT_ID = "google";
  private final ClientDetailsService clientDetailsService;

  @Inject
  public ClientAuthenticationFilter(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {}

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    try {
      String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

      if (Strings.isNullOrEmpty(grantType)) {
        throw new InvalidGrantException(InvalidGrantException.ErrorCode.NO_GRANT_TYPE);
      }

      // Set client for jwt assertion
      if (grantType.equals(OAuth2Constants.GrantType.JWT_ASSERTION)) {
        ClientSession clientSession = OAuth2Utils.getClientSession((HttpServletRequest) request);
        clientSession.setClient(clientDetailsService.getClientByID(GOOGLE_CLIENT_ID).get());
        OAuth2Utils.setClientSession((HttpServletRequest) request, clientSession);
      } else {
        String clientID = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String secret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);

        if (Strings.isNullOrEmpty(clientID)) {
          throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_CLIENT_ID);
        }
        if (Strings.isNullOrEmpty(secret) || !check(clientID, secret)) {
          throw new InvalidClientException();
        }

        // Check success!
        log.info("Client Authenrication:" + clientID + "!");
        ClientSession clientSession = OAuth2Utils.getClientSession((HttpServletRequest) request);
        clientSession.setClient(clientDetailsService.getClientByID(clientID).get());
        OAuth2Utils.setClientSession((HttpServletRequest) request, clientSession);
      }
      chain.doFilter(request, response);
    } catch (OAuth2Exception exception) {
      log.info(
          "Failed in client Authentication."
              + "Error Type: "
              + exception.getErrorType()
              + "Description: "
              + exception.getErrorDescription());
      OAuth2ExceptionHandler.handle(exception, (HttpServletResponse) response);
    }
  }

  private boolean check(String clientID, String secret) {
    Optional<ClientDetails> client = clientDetailsService.getClientByID(clientID);

    if (!client.isPresent()) {
      return false;
    }

    return client
        .get()
        .getSecret()
        .equals(Hashing.sha256().hashString(secret, Charsets.UTF_8).toString());
  }

  @Override
  public void destroy() {}
}
