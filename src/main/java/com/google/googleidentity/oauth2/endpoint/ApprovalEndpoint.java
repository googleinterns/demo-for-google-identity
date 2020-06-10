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

package com.google.googleidentity.oauth2.endpoint;

import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.security.UserSession;
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
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Approval endpoint, display request client and request scopes.
 * Used for getting user's approval.
 */
@Singleton
public class ApprovalEndpoint extends HttpServlet {

    private static final long serialVersionUID = 7L;

    private static final Logger log = Logger.getLogger("ApprovalEndpoint");

    private Configuration configuration;

    public void init() throws ServletException {

        Version version = new Version("2.3.30");
        configuration = new Configuration(version);
        configuration.setServletContextForTemplateLoading(getServletContext(), "template");

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            toApprovalPage(request, response);
        } catch (TemplateException e) {
            log.info("Approval Page Error!");
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            toApprovalPage(request, response);
        } catch (TemplateException e) {
            log.info("Approval Page Error!");
        }
    }

    private void toApprovalPage(HttpServletRequest request, HttpServletResponse response)
            throws IOException, TemplateException {

        OAuth2Request oauth2Request =
                ((ClientSession) request.getSession().getAttribute("client_session"))
                        .getRequest().get();

        Map<String, Object> information = new HashMap<String, Object>();
        information.put("clientID", oauth2Request.getRequestAuth().getClientId());

        List<String> scopes = oauth2Request.getRequestBody().getScopesList();

        StringBuilder sb = new StringBuilder();
        if(scopes.isEmpty()){
            sb.append("All");
        }
        else{
            for(String scope : scopes){
                sb.append(scope + " ");
            }
        }

        information.put("scopes", sb.toString());

        Template template = configuration.getTemplate("ApprovalPage.ftl");

        response.setCharacterEncoding("utf-8");
        PrintWriter printWriter = response.getWriter();

        template.process(information, printWriter);

        printWriter.flush();
    }

}
