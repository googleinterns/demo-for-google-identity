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

import com.google.googleidentity.user.UserDetails;
import com.google.inject.servlet.SessionScoped;

import java.io.Serializable;
import java.util.Optional;

/**
 * ClientSession Object
 * Store client information for a client pass filter
 */
@SessionScoped
public class ClientSession implements Serializable {

    private static final long serialVersionUID = 6L;

    private ClientDetails client = null;

    public Optional<ClientDetails> getClient() {
        return Optional.ofNullable(client);
    }

    public void setClient(ClientDetails client) {
        this.client = client;
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        if (client != null) {
            sb.append("client:" + client.toString() + "\t");
        }
        return sb.toString();
    }

}
