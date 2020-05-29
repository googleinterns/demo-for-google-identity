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


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * OAuth2 Util Library
 */
public class OAuth2Utils {

    /**
     *  Constants in OAuth2 Request
     */
    public static final String CLIENT_ID = "client_id";

    public static final String CLIENT_SECRET = "client_secret";

    public static final String REDIRECT_URI = "redirect_uri";

    public static final String STATE = "state";

    public static final String RESPONSE_TYPE = "response_type";

    public static final String SCOPE = "scope";

    /**
     *
     * @param scope string
     * @return parsed scope set
     */
    public static Set<String> parseScope(String scope){
        if(scope == null){
            return Collections.emptySet();
        }

        String[] scopes = scope.split("\\s+");

        return new HashSet<String>(Arrays.asList(scopes));

    }

    /**
     *
     * @param allowedScopes
     * @param requestScopes
     * @return whether requestScopes are all in allowedScopes
     */
    public static boolean checkScope(Set<String> allowedScopes, Set<String> requestScopes){
        for(String scope : requestScopes){
            if(!allowedScopes.contains(scope)){
                return false;
            }
        }
        return true;
    }
}
