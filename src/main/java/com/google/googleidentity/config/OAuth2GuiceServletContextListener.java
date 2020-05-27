package com.google.googleidentity.config;


import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.GuiceServletContextListener;

public class OAuth2GuiceServletContextListener extends GuiceServletContextListener {
    @Override
    protected Injector getInjector(){
        return Guice.createInjector(new OAuth2Module());
    }
}
