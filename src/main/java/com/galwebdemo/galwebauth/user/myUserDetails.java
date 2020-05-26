package com.galwebdemo.galwebauth.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class myUserDetails implements ExtendedUserDetails {

    private static final long serialVersionUID = 2L;

    private String password;
    private final UserDetails delegate;

    private ExtendedUserInfo extendedUserInfo;

    public myUserDetails(UserDetails user) {
        this.delegate = user;
        this.password = user.getPassword();
        this.extendedUserInfo = new ExtendedUserInfo();
    }

    public Object getExtendedInfo(){
        return extendedUserInfo;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) { this.password = password; }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return delegate.getAuthorities();
    }

    public String getUsername() {
        return delegate.getUsername();
    }

    public boolean isAccountNonExpired() {
        return delegate.isAccountNonExpired();
    }

    public boolean isAccountNonLocked() {
        return delegate.isAccountNonLocked();
    }

    public boolean isCredentialsNonExpired() {
        return delegate.isCredentialsNonExpired();
    }

    public boolean isEnabled() {
        return delegate.isEnabled();
    }


}
