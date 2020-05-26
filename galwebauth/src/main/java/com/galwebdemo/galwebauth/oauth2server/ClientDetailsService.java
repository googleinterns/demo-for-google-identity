package com.galwebdemo.galwebauth.oauth2server;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

//Manage the client information
public interface ClientDetailsService {

    ClientDetails getClientById(String clientId);

    void addClient(ClientDetails clientDetails);

    void updateClientDetails(ClientDetails clientDetails);

    void removeClientDetails(String clientId);

    PasswordEncoder getPasswordEncoder();

    List<ClientDetails> listClientDetails();

}
