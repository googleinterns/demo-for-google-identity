package com.galwebdemo.galwebauth.user;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.core.userdetails.memory.UserAttributeEditor;
import org.springframework.util.Assert;

import java.util.*;

public class InMemoryUserDetailsService implements ExtendedUserDetailsService {

    private Map<String, myUserDetails> userDetailsStore = new HashMap<String, myUserDetails>();

    public InMemoryUserDetailsService() {
    }

    public void setUserDetailsStore(Map<String, ? extends myUserDetails> userDetailsStore) {
        this.userDetailsStore = new HashMap<String, myUserDetails>(userDetailsStore);
    }

    public void createUser(UserDetails user) {

        Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
        userDetailsStore.put(user.getUsername(), new myUserDetails(user));
    }

    public void updateUser(UserDetails user) {
        userDetailsStore.put(user.getUsername(), new myUserDetails(user));
    }


    public void deleteUser(String username) {
        userDetailsStore.remove(username);
    }


    public boolean userExists(String username) {
        return userDetailsStore.containsKey(username);
    }

    public ExtendedUserDetails GetExistingUser(String email, long googleAccountId) {
        for(Map.Entry<String, myUserDetails> user : userDetailsStore.entrySet()){
            ExtendedUserInfo userinfo= (ExtendedUserInfo)user.getValue().getExtendedInfo();
            if (userinfo.getGoogleAccountId() == googleAccountId || userinfo.getEmail().equals(email)){
                return user.getValue();
            }
        }
        return null;
    }


    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (currentUser == null) {
            throw new AccessDeniedException("No ");
        }

        String username = currentUser.getName();

        myUserDetails user = userDetailsStore.get(username);

        if (user == null) {
            throw new IllegalStateException("Current user doesn't exist in database.");
        }

        user.setPassword(newPassword);
    }


    public UserDetails updatePassword(UserDetails user, String newPassword) {
        String username = user.getUsername();
        ExtendedUserDetails extendedUser = this.userDetailsStore.get(username);
        extendedUser.setPassword(newPassword);
        return extendedUser;
    }


    public UserDetails loadUserByUsername(String username)  throws UsernameNotFoundException {
        UserDetails user = userDetailsStore.get(username);

        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return user;
    }

}
