package com.galwebdemo.galwebauth.oauth2server;

import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

//client details for store, client_id, client_secret, grant_type, redirectUri, authorities and extensions
public interface ClientDetails extends Serializable {

    String getClientId();

    String getClientSecret();

    boolean isScoped();

    Set<String> getScope();

    Set<String> getAuthorizedGrantTypes();

    Set<String> getRedirectUri();

    Collection<GrantedAuthority> getAuthorities();

    Set<String> getResourceIds();

    Map<String, Object> getAdditionalInformation();

    Integer getAccessTokenValiditySeconds();

    Integer getRefreshTokenValiditySeconds();
}
