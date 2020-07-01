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

package com.google.googleidentity.oauth2.exception;

import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import net.minidev.json.JSONObject;
import org.apache.http.client.utils.URIBuilder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * class to handle {@link OAuth2Exception}
 */
public final class OAuth2ExceptionHandler {

    private static final Logger log = Logger.getLogger("OAuth2ExceptionHandler");

    private static final String ERROR_DESCRIPTION = "error_description";
    private static final String ERROR = "error";

    /**
     * Used to return json error response
     */
    public static void handle(OAuth2Exception exception, HttpServletResponse response)
            throws IOException {
        response.setStatus(exception.getHttpCode());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(getResponseBody(exception).toJSONString());
        response.getWriter().flush();
    }

    /**
     * Used to get json error response
     */
    public static JSONObject getResponseBody(OAuth2Exception exception) {
        JSONObject json =  new JSONObject();
        json.appendField(ERROR, exception.getErrorType());
        if (!Strings.isNullOrEmpty(exception.getErrorDescription())) {
            json.appendField(ERROR_DESCRIPTION, exception.getErrorDescription());
        }
        return json;
    }

    /**
     * According to RFC6749, if the resource owner denies the access request or if the request
     * fails for reasons other than a missing or invalid redirection URI, redirect and send the
     * error message.
     */
    public static String getFullRedirectUrl(
            OAuth2Exception exception, String redirectUri, String state) {
        try {
            URIBuilder uriBuilder = new URIBuilder(redirectUri)
                    .addParameter(ERROR, exception.getErrorType());
            if (Strings.isNullOrEmpty(exception.getErrorDescription())) {
                uriBuilder.addParameter(
                        ERROR_DESCRIPTION, exception.getErrorDescription());
            }
            if(Strings.isNullOrEmpty(state)) {
                uriBuilder.addParameter(OAuth2ParameterNames.STATE, state);
            }
            return uriBuilder.build().toString();
        } catch (URISyntaxException e) {
            log.log(Level.INFO, "URI ERROR!", e);
        }
        return null;
    }
}
