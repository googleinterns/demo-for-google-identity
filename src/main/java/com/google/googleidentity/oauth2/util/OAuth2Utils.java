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
import java.util.Set;

/**
 * OAuth2 Util Library
 */
public class OAuth2Utils {

    /**
     *
     * @param scope string
     * @return parsed scope set
     */
    public static Set<String> parseScope(String scope){
        if(scope == null){
            return ImmutableSet.of();
        }

        String[] scopes = scope.split("\\s+");

        return ImmutableSet.copyOf(scopes);

    }

    /**
     * Get UserSession from HttpSession
     *
     * @param request
     * @return
     */
    public static UserSession getUserSession(HttpServletRequest request){
        UserSession userSession =
                (UserSession) request.getSession().getAttribute("user_session");

        return userSession == null ? new UserSession() : userSession;

    }

    /**
     * Set UserSession to HttpSession
     *
     * @param request
     */
    public static void setUserSession(
            HttpServletRequest request, UserSession userSession){
        request.getSession().setAttribute("user_session", userSession);
    }

    /**
     * Get ClientSession from HttpSession
     *
     * @param request
     * @return
     */
    public static ClientSession getClientSession(HttpServletRequest request){
        ClientSession clientSession =
                (ClientSession) request.getSession().getAttribute("client_session");

        return clientSession == null ? new ClientSession() : clientSession;
    }

    /**
     * Set ClientSession to HttpSession
     *
     * @param request
     */
    public static void setClientSession(
            HttpServletRequest request, ClientSession clientSession){
        request.getSession().setAttribute("client_session", clientSession);
    }
}
