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

import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import net.minidev.json.JSONObject;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;

import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.google.googleidentity.oauth2.exception.OAuth2Exception.ErrorCode;

/**
 * class to handle {@link OAuth2Exception}
 */
public final class OAuth2ExceptionHandler {

    private static final Logger log = Logger.getLogger("OAuth2ExceptionHandler");

    /**
     * Used when return json error response
     */
    public static JSONObject getResponseBody(OAuth2Exception exception){
        JSONObject json =  new JSONObject();
        json.appendField("error", exception.getErrorType());
        if (exception.getErrorDescription() != null) {
            json.appendField("error_description", exception.getErrorDescription());
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
        ErrorCode code = exception.getErrorCode();
        try {
            URIBuilder uriBuilder = new URIBuilder(redirectUri)
                    .addParameter("error", exception.getErrorType());
            if (exception.getErrorDescription() != null) {
                uriBuilder.addParameter(
                        "error_description", exception.getErrorDescription());
            }
            if(state != null) {
                uriBuilder.addParameter(OAuth2ParameterNames.STATE, state);
            }
            return uriBuilder.build().toString();
        } catch (URISyntaxException e) {
            log.log(Level.INFO, "URI ERROR!", e);
        }
        return null;
    }
}
