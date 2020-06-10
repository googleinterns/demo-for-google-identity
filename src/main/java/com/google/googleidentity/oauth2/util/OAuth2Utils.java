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
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import net.minidev.json.JSONObject;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * OAuth2 Util Library
 */
public class OAuth2Utils {

    /**
     * Return oauth2 exception error through response.
     * @param response
     * @param exception
     * @throws IOException
     */
    public static void returnHttpError(
            HttpServletResponse response, OAuth2Exception exception) throws IOException {
        response.setStatus(exception.getCode());
        response.setContentType("application/json");

        JSONObject json =  new JSONObject();
        json.appendField("error", exception.getErrorType().get());
        if(exception.getErrorInfo().isPresent()){
            json.appendField("info", exception.getErrorInfo().get());
        }
        if(exception.getInformation().isPresent()){
            for(Map.Entry<String, String> entry : exception.getInformation().get().entrySet()){
                json.appendField(entry.getKey(), entry.getValue());
            }
        }

        response.getWriter().println(json.toJSONString());

        response.getWriter().flush();
    }

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
}
