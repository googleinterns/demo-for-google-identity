package com.google.googleidentity.user;

import java.io.Serializable;

public interface UserDetails extends Serializable {

    String getUsername();

    String getPassword();

    void setPassword(String password);

    void setAdditionalInformation(Object additionalInformation);

    Object getAdditionalInformation();
}
