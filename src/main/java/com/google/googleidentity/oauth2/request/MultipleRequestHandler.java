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

package com.google.googleidentity.oauth2.request;

import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.UnsupportedGrantTypeException;

import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.inject.Inject;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Make multiple grant type available.
 */
public class MultipleRequestHandler implements RequestHandler {

    private final Map<GrantType, RequestHandler> requestHandlerMap;

    @Inject
    public MultipleRequestHandler(Map<GrantType, RequestHandler> requestHandlerMap) {
        this.requestHandlerMap = requestHandlerMap;
    }

    public void handle(HttpServletResponse response, OAuth2Request oauth2Request)
            throws IOException, OAuth2Exception {
        if (requestHandlerMap.containsKey(oauth2Request.getRequestBody().getGrantType())) {
            requestHandlerMap.get(oauth2Request.getRequestBody().getGrantType())
                    .handle(response, oauth2Request);
        } else {
            throw new UnsupportedGrantTypeException();
        }
    }

}
