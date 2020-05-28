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

package com.google.googleidentity.security;

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

/**
 * Demo Login Servlet
 * Just Bind the login Servlet with a freemarker template.
 */

@Singleton
public final class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private Configuration configuration;

    public void init() throws ServletException {
        Version version = new Version("2.3.30");

        configuration = new Configuration(version);

        configuration.setServletContextForTemplateLoading(getServletContext(), "template");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            loginPage(request,  response);
        } catch (TemplateException e) {
            e.printStackTrace();
        }

    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
            loginPage(request,  response);
        } catch (TemplateException e) {
            e.printStackTrace();
        }

    }

    private void loginPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, TemplateException {

        Template template = configuration.getTemplate("Login.ftl");

        Map<String, Object> information = new HashMap<String, Object>();

        response.setCharacterEncoding("utf-8");

        PrintWriter printWriter = response.getWriter();

        template.process(information, printWriter);

        printWriter.flush();

    }

}

