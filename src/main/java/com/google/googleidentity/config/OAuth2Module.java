package com.google.googleidentity.config;

import com.google.googleidentity.security.LoginCheckServlet;
import com.google.googleidentity.security.LoginServlet;
import com.google.googleidentity.filter.UserAuthenticationFilter;
import com.google.googleidentity.resource.UserServlet;
import com.google.googleidentity.user.DefaultUserDetails;
import com.google.googleidentity.user.UserDetails;
import com.google.inject.AbstractModule;
import com.google.inject.servlet.ServletModule;

public class OAuth2Module extends AbstractModule {
    @Override
    protected void configure(){
        install(new ServletModule(){
            @Override
            protected void configureServlets(){
                serve("/resource/user").with(UserServlet.class);
                //support urlRewrite(with jsessionid)
                serveRegex("/login", "/login;jsessionid.*").with(LoginServlet.class);
                serve("/login_check").with(LoginCheckServlet.class);
                filterRegex("/oauth2/authorize",  "/resource/.*").through(UserAuthenticationFilter.class);
            }
        });
        bind(UserDetails.class).to(DefaultUserDetails.class);
    }
}
