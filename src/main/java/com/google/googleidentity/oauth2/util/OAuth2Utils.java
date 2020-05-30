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
import com.google.googleidentity.oauth2.client.ClientDetails;

import java.util.HashSet;
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
            return new HashSet<String>();
        }

        String[] scopes = scope.split("\\s+");

        return ImmutableSet.copyOf(scopes);

    }

    /**
     *
     * @param client
     * @param requestScopes
     * @return whether requestScopes are all in allowedScopes
     */
    public static boolean checkScope(ClientDetails client, Set<String> requestScopes){

        if(client.getIsScoped() == false){
            return true;
        }

        Set<String> allowedScopes = ImmutableSet.copyOf(client.getScopeList());

        for(String scope : requestScopes){
            if(!allowedScopes.contains(scope)){
                return false;
            }
        }
        return true;
    }
}
