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

package com.google.googleidentity.resource;


import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.UserDetails;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Demo UserServlet
 * Read UserDetails.User Object {@link com.google.googleidentity.user.UserDetails}  stored in
 * in the session through class {@link com.google.googleidentity.security.UserSession} and
 * display the username.
 */
@Singleton
public final class UserServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger("UserServlet");

    private final Provider<UserSession> session;

    private Configuration configuration;

    @Inject
    public UserServlet(Provider<UserSession> session) {
        this.session = session;
    }

    public void init() throws ServletException {

        Version version = new Version("2.3.30");
        configuration = new Configuration(version);
        configuration.setServletContextForTemplateLoading(getServletContext(), "template");

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            displayMainPage(request, response);
        } catch (TemplateException e) {
            log.info("MainPage Error!");
        }

    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            displayMainPage(request, response);
        } catch (TemplateException e) {
            log.info("MainPage Error!");
        }

    }

    private void displayMainPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, TemplateException {

        UserSession userSession = session.get();
        UserDetails user = userSession.getUser().get();

        Map<String, Object> information = new HashMap<String, Object>();
        information.put("username", user.getUsername());

        Template template = configuration.getTemplate("MainPage.ftl");

        response.setCharacterEncoding("utf-8");
        PrintWriter printWriter = response.getWriter();

        template.process(information, printWriter);

        printWriter.flush();

    }

}
