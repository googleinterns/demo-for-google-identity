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


import com.google.common.base.Preconditions;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default InMemory ClientDetailsService for client information Store
 * An Implementation for {@link ClientDetailsService}
 */
public class InMemoryClientDetailsService implements ClientDetailsService{

    private ConcurrentHashMap<String, ClientDetails.Client> clientStore
            = new ConcurrentHashMap<>();

    @Override
    public ClientDetails.Client getClientByID(String clientID) {
        return clientStore.getOrDefault(clientID, null);
    }

    @Override
    public boolean updateClient(ClientDetails.Client client) {

        Preconditions.checkNotNull(client);

        String clientID = client.getClientID();
        if (clientID.isEmpty()) {
            return false;
        }
        if (!clientStore.containsKey(clientID)) {
            return false;
        }
        clientStore.put(clientID, client);
        return true;
    }

    @Override
    public boolean addClient(ClientDetails.Client client) {

        Preconditions.checkNotNull(client);

        String clientID = client.getClientID();
        if (clientID.isEmpty()) {
            return false;
        }
        if (clientStore.containsKey(clientID)) {
            return false;
        }
        clientStore.put(clientID, client);
        return true;
    }

    @Override
    public List<ClientDetails.Client> listClient() {
        return new ArrayList<ClientDetails.Client>(clientStore.values());
    }
}

