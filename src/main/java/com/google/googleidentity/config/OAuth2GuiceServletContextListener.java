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

/**
 * Start GuiceServlet, Create an Injector for Guice in OAuth2Module{@OAuth2Module}
 */

package com.google.googleidentity.config;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.GuiceServletContextListener;

/**
 * Start Guice Servlet, Create an Injector for Guice using {@link com.google.googleidentity.config.OAuth2Module}.
 */


public class OAuth2GuiceServletContextListener extends GuiceServletContextListener {
    @Override
    protected Injector getInjector(){
        return Guice.createInjector(new OAuth2Module());
    }

}
