package com.google.googleidentity.filter;



import com.google.googleidentity.security.UserSession;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;


import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

@Singleton
public class UserAuthenticationFilter implements Filter {

    private static final long serialVersionUID = 1L;

    @Inject
    private Provider<UserSession> session = null;

    public void init(FilterConfig filterConfig) throws ServletException {

    }
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletResponse httpresponse = (HttpServletResponse) response;

        HttpServletRequest httprequest = (HttpServletRequest) request;

        UserSession usersession = session.get();

        usersession.setOlduri(httprequest.getRequestURI());

      //  System.out.println(httprequest.getRequestURI());

        if(usersession.getUser() == null){
            httpresponse.sendRedirect("/login");
        }
        else{
            chain.doFilter(request,  response);
        }
    }
    public void destroy() { }

}
