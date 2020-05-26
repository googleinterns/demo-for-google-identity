package com.galwebdemo.galwebauth.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface ExtendedUserDetailsService extends UserDetailsService {

    void createUser(UserDetails user);


    void updateUser(UserDetails user);


    void deleteUser(String username);


    void changePassword(String oldPassword, String newPassword);

    UserDetails updatePassword(UserDetails user, String newPassword);

    boolean userExists(String username);

    ExtendedUserDetails GetExistingUser(String email, long googleAccountId);


}
