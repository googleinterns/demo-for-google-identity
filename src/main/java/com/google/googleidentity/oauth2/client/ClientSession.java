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

package com.google.googleidentity.oauth2.client;

import com.google.googleidentity.oauth2.request.OAuth2Request;

import java.io.Serializable;
import java.util.Optional;

/**
 * ClientSession Object
 * Store client information for a client passed filter
 * Store request information
 * Stored in HttpSession named client_session
 */
public final class ClientSession implements Serializable {

    private static final long serialVersionUID = 6L;

    private ClientDetails client = null;

    private OAuth2Request request = null;

    public Optional<ClientDetails> getClient() {
        return Optional.ofNullable(client);
    }

    public Optional<OAuth2Request> getRequest(){
        return Optional.ofNullable(request);
    }

    public void setClient(ClientDetails client) {
        this.client = client;
    }

    public void setRequest(OAuth2Request request){
        this.request = request;
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        if (client != null) {
            sb.append("client:" + client.toString() + "\t");
        }
        if (request != null) {
            sb.append("request:" + request.toString() + "\t" );
        }
        return sb.toString();
    }

}
