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


import com.google.googleidentity.security.UserSession;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import org.apache.http.client.utils.URIBuilder;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The filter to protect resources using username password authentication.
 * Once A user logged in, A UserDetails.User Object
 * {@link com.google.googleidentity.user.UserDetails} will stored
 * in the session through class {@link com.google.googleidentity.security.UserSession}.
 * If the object in the session is null, then the request will be blocked and
 * redirected to login page.
 * The original request will be stored in the session through class
 * {@link com.google.googleidentity.security.UserSession}.
 */
@Singleton
public final class UserAuthenticationFilter implements Filter {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger("UserAuthenticationFilter");

    private final Provider<UserSession> session;

    @Inject
    public UserAuthenticationFilter(Provider<UserSession> session) {
        this.session = session;
    }

    public void init(FilterConfig filterConfig) throws ServletException {}

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        UserSession userSession = session.get();
        userSession.setOlduri(null);

        if (userSession.getUser().isPresent()) {
            chain.doFilter(request, response);
        }
        else {
            try {
                userSession.setOlduri(fetchOldUri(httpRequest));
            } catch (URISyntaxException e) {
                log.log(Level.INFO, "URI Error!", e);
            }
            httpResponse.sendRedirect("/login");
        }
    }

    private String fetchOldUri(HttpServletRequest httpRequest) throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(httpRequest.getRequestURI());
        for(Map.Entry<String, String[]> entry : httpRequest.getParameterMap().entrySet()){
            uriBuilder.addParameter(entry.getKey(), entry.getValue()[0]);
        }
        return uriBuilder.build().toString();
    }

    public void destroy() {
    }

}
