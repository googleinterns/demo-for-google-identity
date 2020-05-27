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

@Singleton
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Inject
    private Provider<UserSession> session = null;

    private Configuration configuration;

    public void init() throws ServletException {
        Version version= new Version("2.3.30");

        configuration = new Configuration(version);

        configuration.setServletContextForTemplateLoading(getServletContext(), "template");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        try {
            LoginPage(request,  response);
        } catch (TemplateException e) {
            e.printStackTrace();
        }


    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        try {
            LoginPage(request,  response);
        } catch (TemplateException e) {
            e.printStackTrace();
        }

    }

    private void LoginPage(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, TemplateException {

        Template template = configuration.getTemplate("Login.ftl");

        Map<String, Object> information = new HashMap<String, Object>();

        response.setCharacterEncoding("utf-8");

        PrintWriter printWriter = response.getWriter();

        template.process(information, printWriter);

        printWriter.flush();

    }

}

