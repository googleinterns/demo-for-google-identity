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

package com.google.googleidentity.servlet;

import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Singleton
public class RegisterServlet extends HttpServlet {

  private static final long serialVersionUID = 15L;

  private static final Logger log = Logger.getLogger("RegisterServlet");

  private Configuration configuration;

  public void init() throws ServletException {
    Version version = new Version("2.3.30");

    configuration = new Configuration(version);

    configuration.setServletContextForTemplateLoading(getServletContext(), "template");
  }

  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

    try {
      displayPage(response);
    } catch (TemplateException e) {
      throw new OAuth2ServerException("Error when display register page", e);
    }
  }


  private void displayPage(HttpServletResponse response)
      throws ServletException, IOException, TemplateException {

    Template template = configuration.getTemplate("Register.ftl");
    Map<String, Object> information = new HashMap<>();
    response.setCharacterEncoding("utf-8");
    PrintWriter printWriter = response.getWriter();
    template.process(information, printWriter);
    printWriter.flush();
  }
}
