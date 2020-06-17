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

/**
 * class to handle {@link OAuth2Exception}
 */
public final class OAuth2ExceptionHandler {

    private static final Logger log = Logger.getLogger("OAuth2ExceptionHandler");

    private static final String INVALID_REQUEST = "invalid_request";
    private static final String INVALID_GRANT = "invalid_grant";
    private static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    private static final String INVALID_CLIENT = "invalid_client";
    private static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    private static final String INVALID_SCOPE = "invalid_scope";
    private static final String ACCESS_DENIED = "access_denied";
    private static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

    public enum ErrorCode{
        NO_RESPONSE_TYPE,
        UNSUPPORTED_RESPONSE_TYPE,
        NO_CLIENT_ID,
        NONEXISTENT_CLIENT_ID,
        UNAUTHORIZED_CLIENT,
        NO_REDIRECT_URI,
        REDIRECT_URI_MISMATCH,
        INVALID_SCOPE,
        ACCESS_DENIED,
        NO_GRANT_TYPE,
        UNSUPPORTED_GRANT_TYPE,
        NONEXISTENT_CODE,
        CODE_CLIENT_MISMATCH,
        CODE_REDIRECT_URI_MISMATCH,
        INVALID_CLIENT,
        NONEXISTENT_REFRESH_TOKEN,
        REFRESH_TOKEN_CLIENT_MISMATCH
    }

    public static int getHttpCode(ErrorCode code){
        if(code.equals(ErrorCode.INVALID_CLIENT)){
            return HttpStatus.SC_UNAUTHORIZED;
        }
        else{
            return HttpStatus.SC_BAD_REQUEST;
        }
    }

    public static String getErrorType(ErrorCode code){
        switch(code){
            case NO_RESPONSE_TYPE:
            case NO_CLIENT_ID:
            case NONEXISTENT_CLIENT_ID:
            case NO_REDIRECT_URI:
                // fall through
            case REDIRECT_URI_MISMATCH:
                return INVALID_REQUEST;
            case INVALID_SCOPE:
                return INVALID_SCOPE;
            case UNSUPPORTED_RESPONSE_TYPE:
                return UNSUPPORTED_RESPONSE_TYPE;
            case UNAUTHORIZED_CLIENT:
                return UNAUTHORIZED_CLIENT;
            case ACCESS_DENIED:
                return ACCESS_DENIED;
            case NONEXISTENT_CODE:
            case CODE_CLIENT_MISMATCH:
            case CODE_REDIRECT_URI_MISMATCH:
            case NONEXISTENT_REFRESH_TOKEN:
            case REFRESH_TOKEN_CLIENT_MISMATCH:
                // fall through
            case NO_GRANT_TYPE:
                return INVALID_GRANT;
            case UNSUPPORTED_GRANT_TYPE:
                return UNSUPPORTED_GRANT_TYPE;
            case INVALID_CLIENT:
                return INVALID_CLIENT;
            default:
                throw new IllegalArgumentException();
        }
    }


    public static String getErrorDescription(ErrorCode code){
        switch(code){
            case NO_RESPONSE_TYPE:
                return "No Response Type!";
            case UNSUPPORTED_RESPONSE_TYPE:
                return "Unsupported Response Type!";
            case NO_CLIENT_ID:
                return "No Client ID!";
            case NONEXISTENT_CLIENT_ID:
                return "Client ID does not exist!";
            case UNAUTHORIZED_CLIENT:
                return "The client is not allowed to use this method!";
            case NO_REDIRECT_URI:
                return "No Redirect Uri!";
            case REDIRECT_URI_MISMATCH:
                return "Redirect Uri Mismatch!";
            case ACCESS_DENIED:
                return "User denied the access!";
            case INVALID_SCOPE:
                return "Invalid scopes!";
            case NONEXISTENT_CODE:
                return "Non existing code!";
            case CODE_CLIENT_MISMATCH:
                return "Code client mismatch!";
            case NO_GRANT_TYPE:
                return "No grant type!";
            case CODE_REDIRECT_URI_MISMATCH:
                return "Redirect uri mismatches the grant!";
            case UNSUPPORTED_GRANT_TYPE:
                return "Unsupported grant type!";
            case INVALID_CLIENT:
                return "Client Authentication Failed!";
            case NONEXISTENT_REFRESH_TOKEN:
                return "Refresh token does not exist!";
            case REFRESH_TOKEN_CLIENT_MISMATCH:
                return "Refresh token and client mismatch!";
            default:
                throw new IllegalArgumentException();
        }
    }

    /**
     * Used when return json error response
     */
    public static JSONObject getResponseBody(OAuth2Exception exception){
        ErrorCode code = exception.getErrorCode();
        JSONObject json =  new JSONObject();
        json.appendField("error", getErrorType(code));
        json.appendField("error_description", getErrorDescription(code));
        return json;
    }

    /**
    * Used in AuthorizationEndpoint.
    * According to RFC6749, if the request fails due to a missing, invalid, or mismatching
    * redirection URI, or if the client identifier is missing or invalid, the authorization
    * server SHOULD inform the resource owner of the error and MUST NOT automatically
    * redirect the user-agent to the invalid redirection URI.
    */
    public static boolean isRedirectable(ErrorCode code) {
        switch(code){
            case NO_REDIRECT_URI:
            case REDIRECT_URI_MISMATCH:
            case NO_CLIENT_ID:
            case NONEXISTENT_CLIENT_ID:
                // fall through
            case UNAUTHORIZED_CLIENT:
                return false;
            case NO_RESPONSE_TYPE:
            case INVALID_SCOPE:
            case UNSUPPORTED_RESPONSE_TYPE:
                // fall through
            case ACCESS_DENIED:
                return true;
            default:
                throw new IllegalArgumentException();
        }
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
                    .addParameter("error", getErrorType(code))
                    .addParameter("error_description", getErrorDescription(code));
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
