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

package com.google.googleidentity.oauth2.util;

import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.security.UserSession;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;

/**
 * OAuth2 Util Library
 */
public class OAuth2Utils {

    private static final String USER_SESSION = "user_session";
    private static final String CLIENT_SESSION = "client_session";

    /**
     *
     * @param scope string of scopes with space delimiter
     * @return parsed scope set
     */
    public static Set<String> parseScope(String scope) {
        if (scope == null) {
            return ImmutableSet.of();
        }

        String[] scopes = scope.split("\\s+");

        return ImmutableSet.copyOf(scopes);

    }

    /**
     * @return whether the uri matches one of the uri in uriList of a client
     */
    public static boolean matchUri(List<String> uriList, String uri) {
        for (String eachPattern : uriList) {
            if (uri.startsWith(eachPattern)) {
                //match exactly same uris
                if (eachPattern.equals(uri)) {
                    return true;
                }
                //match uris like abc.com/xyz to registered uri abc.com/
                if (eachPattern.charAt(eachPattern.length()-1) == '/') {
                    return true;
                }
                //match uris like abc.com/xyz to registered uri abc.com
                if (uri.length()>eachPattern.length() && uri.charAt(eachPattern.length()) == '/') {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get UserSession from HttpSession
     */
    public static UserSession getUserSession(HttpServletRequest request) {
        UserSession userSession =
                (UserSession) request.getSession().getAttribute(USER_SESSION);

        return userSession == null ? new UserSession() : userSession;

    }

    /**
     * Set UserSession to HttpSession
     */
    public static void setUserSession(
            HttpServletRequest request, UserSession userSession) {
        request.getSession().setAttribute(USER_SESSION, userSession);
    }

    /**
     * Get ClientSession from HttpSession
     */
    public static ClientSession getClientSession(HttpServletRequest request) {
        ClientSession clientSession =
                (ClientSession) request.getSession().getAttribute(CLIENT_SESSION);

        return clientSession == null ? new ClientSession() : clientSession;
    }

    /**
     * Set ClientSession to HttpSession
     */
    public static void setClientSession(
            HttpServletRequest request, ClientSession clientSession) {
        request.getSession().setAttribute(CLIENT_SESSION, clientSession);
    }
}
