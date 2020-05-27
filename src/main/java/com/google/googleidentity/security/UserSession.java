package com.google.googleidentity.security;

import com.google.googleidentity.user.UserDetails;
import com.google.inject.servlet.SessionScoped;

import java.io.Serializable;

@SessionScoped
public class UserSession implements Serializable {

    private static final long serialVersionUID = 3L;

    private UserDetails user = null;

    private String olduri = "";

    public UserDetails getUser(){
        return user;
    }

    public String getOlduri(){
        return olduri;
    }

    public void setUser(UserDetails user){
        this.user = user;
    }

    public void setOlduri(String olduri){
        this.olduri = olduri;
    }

    public String toString(){
        if(user != null) {
            return "user:" + user.toString() + "\tolduri:" + olduri;
        }
        else{
            return "olduri:" + olduri;
        }
    }


}
