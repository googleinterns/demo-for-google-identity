package com.galwebdemo.galwebauth.user;

import java.io.Serializable;

//extra information for users
public class ExtendedUserInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private long googleAccountId;

    private String email;

    ExtendedUserInfo(){
        googleAccountId= -1;
        email =" ";
    }

    public ExtendedUserInfo(long googleAccountId, String email){
        this.googleAccountId = googleAccountId;
        this.email = email;
    }

    public long getGoogleAccountId(){
        return googleAccountId;
    }

    public String getEmail(){
        return email;
    }

    public String toString(){
        return "email:" + email + "\tgoogleAccountId:" + googleAccountId;
    }

}
