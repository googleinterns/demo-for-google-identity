package com.galwebdemo.galwebauth.user;

import org.springframework.security.core.userdetails.UserDetails;

public interface ExtendedUserDetails extends UserDetails {

    void setPassword(String password);

    Object getExtendedInfo();
}
