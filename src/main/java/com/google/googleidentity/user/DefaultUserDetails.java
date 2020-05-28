/*
    Copyright 2020 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

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
