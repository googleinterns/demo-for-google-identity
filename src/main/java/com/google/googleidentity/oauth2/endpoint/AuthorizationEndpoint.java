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

import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.security.UserSession;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Demo AuthorizationEndpoint for OAuth2 Server
 */
@Singleton
public final class AuthorizationEndpoint extends HttpServlet {

    private static final long serialVersionUID = 5L;

    private static final Logger log = Logger.getLogger("AuthorizationCodeEndpoint");

    private final ClientDetailsService clientDetailsService;


    @Inject
    public AuthorizationEndpoint(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException{

        try {
            String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);

            if (responseType == null) {
                throw new OAuth2Exception(
                        HttpStatus.SC_BAD_REQUEST, "invalid_request", "No Response Type!");
            }
            else if (!responseType.equals("token") && !responseType.equals("code")) {
                throw new OAuth2Exception(
                        HttpStatus.SC_BAD_REQUEST, "invalid_request", "Invalid Response Type!");
            }
        }
        catch(OAuth2Exception exception){
            log.info(exception.getErrorInfo().orElse(""));
            OAuth2Utils.returnHttpError(response, exception);
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException{
    }

}

