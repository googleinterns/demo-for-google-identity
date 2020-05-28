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


import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

@Singleton
public final class UserAuthenticationFilter implements Filter {

    private static final long serialVersionUID = 1L;

    @Inject
    private final Provider<UserSession> session;

    @Inject
    public UserAuthenticationFilter(Provider<UserSession> session){
        this.session = session;
    }

    public void init(FilterConfig filterConfig) throws ServletException {

    }
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletResponse httpresponse = (HttpServletResponse) response;

        HttpServletRequest httprequest = (HttpServletRequest) request;

        UserSession usersession = session.get();


        if(httprequest.getQueryString() != null) {
            usersession.setOlduri(httprequest.getRequestURI() + "?" + httprequest.getQueryString());
        }
        else{
            usersession.setOlduri(httprequest.getRequestURI());
        }

        if(usersession.getUser() == null){
            httpresponse.sendRedirect("/login");
        }
        else{
            chain.doFilter(request,  response);
        }
    }
    public void destroy() { }

}
