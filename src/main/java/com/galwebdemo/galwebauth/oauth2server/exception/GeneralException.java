package com.galwebdemo.galwebauth.oauth2server.exception;


//General Error
public class GeneralException extends OAuth2Exception {

    public GeneralException(String msg, Throwable t) {
        super(msg, t);
    }

    public GeneralException(String msg) {
        super(msg);
    }

    @Override
    public String getErrorCode() {
        return "GeneralError";
    }
}
