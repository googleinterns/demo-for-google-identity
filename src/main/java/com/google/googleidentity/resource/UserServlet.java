package com.google.googleidentity.resource;


import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.DefaultUserDetails;
import com.google.googleidentity.user.UserDetails;
import com.google.inject.Inject;
import com.google.inject.Provider;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import com.google.inject.Singleton;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.Version;


@Singleton
public class UserServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Inject
    private Provider<UserSession> session = null;

    private Configuration configuration;

    public void init() throws ServletException{
        Version version= new Version("2.3.30");

        configuration = new Configuration(version);

        configuration.setServletContextForTemplateLoading(getServletContext(), "template");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        try {
            MainPage(request,  response);
        } catch (TemplateException e) {
            e.printStackTrace();
        }


    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        try {
            MainPage(request,  response);
        } catch (TemplateException e) {
            e.printStackTrace();
        }

    }

    private void MainPage(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, TemplateException {

        UserSession usersession = session.get();

        UserDetails user = usersession.getUser();

        Map<String, Object> information = new HashMap<String, Object>();

        information.put("username", user.getUsername());

        Template template = configuration.getTemplate("MainPage.ftl");

        response.setCharacterEncoding("utf-8");

        PrintWriter printWriter = response.getWriter();

        template.process(information, printWriter);

        printWriter.flush();

    }

}
