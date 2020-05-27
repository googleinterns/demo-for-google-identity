package com.google.googleidentity.user;

import java.util.Collections;
import java.util.List;

import com.google.inject.Inject;
import org.apache.commons.lang3.StringUtils;

public class DefaultUserDetails implements UserDetails {
    private static final long serialVersionUID = 2L;

    private String username="";

    private String password="";

    private List<String> authority = Collections.emptyList();

    private Object additionalInformation;

    @Inject
    public DefaultUserDetails(String username, String password, Object addtionalInformation){
        this.username = username;
        this.password = password;
        this.additionalInformation = addtionalInformation;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password =  password;
    }

    public void setAdditionalInformation(Object additionalInformation){
        this.additionalInformation = additionalInformation;
    }

    public Object getAdditionalInformation() {
        return additionalInformation;
    }

    @Override
    public String toString(){
        if( additionalInformation != null) {
            return "username:" + username + "\tpassword:" + password + "\tauthority:" + StringUtils.join(authority) + "additionalinformation:" + additionalInformation.toString();
        }
        else{
            return "username:" + username + "\tpassword:" + password + "\tauthority:" + StringUtils.join(authority);
        }
    }


}
