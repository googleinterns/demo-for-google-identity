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

package com.google.googleidentity.filter;

import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.user.UserSession;
import com.google.inject.Singleton;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.utils.URIBuilder;

@Singleton
public class ClientLoginFilter implements Filter {

  private static final long serialVersionUID = 21L;

  private static final Logger log = Logger.getLogger("ClientLoginFilter");

  public void init(FilterConfig filterConfig) throws ServletException {}

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    HttpServletResponse httpResponse = (HttpServletResponse) response;
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    UserSession userSession = OAuth2Utils.getUserSession(httpRequest);

    // clear the olduri before since it will no longer be used
    userSession.setOlduri(null);

    if (userSession.getClient().isPresent()) {
      OAuth2Utils.setUserSession(httpRequest, userSession);
      chain.doFilter(request, response);
    } else {
      try {
        userSession.setOlduri(fetchOldUri(httpRequest));
      } catch (URISyntaxException e) {
        throw new OAuth2ServerException( "Fetch old uri error!", e);
      }
      OAuth2Utils.setUserSession(httpRequest, userSession);
      httpResponse.sendRedirect("/login");
    }
  }

  private String fetchOldUri(HttpServletRequest httpRequest) throws URISyntaxException {
    URIBuilder uriBuilder = new URIBuilder(httpRequest.getRequestURI());
    for (Map.Entry<String, String[]> entry : httpRequest.getParameterMap().entrySet()) {
      uriBuilder.addParameter(entry.getKey(), entry.getValue()[0]);
    }
    return uriBuilder.build().toString();
  }

  public void destroy() {}
}
