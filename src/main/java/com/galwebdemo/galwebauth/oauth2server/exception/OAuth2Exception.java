package com.galwebdemo.galwebauth.oauth2server.exception;

import java.util.HashMap;
import java.util.Map;

//OAuth2Exception, refer to org.springframework.security.oauth2.provider.exception
public class OAuth2Exception extends RuntimeException{

    private Map<String, String> information = null;

    public OAuth2Exception(String msg) {
        super(msg);
    }

    public OAuth2Exception(String msg, Throwable cause) {
        super(msg, cause);
    }

    public String getErrorCode(){
        return "invalid_request";
    }

    public int getHttpErrorCode(){
        return 400;
    }

    public Map<String, String> getInformation(){
        return this.information;
    }

    public void addInformation(String key, String value){

        if (this.information == null) {
            this.information = new HashMap<String, String>();
        }
        this.information.put(key, value);
    }

    public static OAuth2Exception create(String errorCode, String errorMessage){
        if (errorMessage == null) {
            errorMessage = errorCode == null ? "OAuth Error" : errorCode;
        }
        return null;
    }

    public static OAuth2Exception valueOf(Map<String, String> errorParams){
        String errorCode = errorParams.get("error");
        String errorMessage = errorParams.containsKey("errorMessage") ? errorParams.get("errorMessage") : null;
        OAuth2Exception ex = create(errorCode, errorMessage);
        for (Map.Entry<String, String> entry : errorParams.entrySet()) {
            String key = entry.getKey();
            if (!key.equals("error") && !key.equals("errorMessage")) {
                ex.addInformation(key, entry.getValue());
            }
        }
        return ex;
    }

    @Override
    public String toString(){

        StringBuilder builder = new StringBuilder();
        String delim = "";
        String error = this.getErrorCode();
        if (error != null) {
            builder.append(delim).append("error=\"").append(error).append("\"");
            delim = ", ";
        }
        String errorMessage = this.getMessage();
        if (errorMessage != null) {
            builder.append(delim).append("error_description=\"").append(errorMessage).append("\"");
            delim = ", ";
        }
        Map<String, String> additionalParams = this.getInformation();
        if (additionalParams != null) {
            for (Map.Entry<String, String> param : additionalParams.entrySet()) {
                builder.append(delim).append(param.getKey()).append("=\"").append(param.getValue()).append("\"");
                delim = ", ";
            }
        }
        return builder.toString();
    }


}
