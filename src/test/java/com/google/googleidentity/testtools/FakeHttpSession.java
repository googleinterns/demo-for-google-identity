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

package com.google.googleidentity.testtools;

import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.user.UserSession;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/** Fake HttpSession implementation , only used for test. */
public class FakeHttpSession implements HttpSession {

  private final Map<String, Object> sessionMap = new HashMap<>();

  @Override
  public long getCreationTime() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public long getLastAccessedTime() {
    throw new UnsupportedOperationException();
  }

  @Override
  public ServletContext getServletContext() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getMaxInactiveInterval() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setMaxInactiveInterval(int interval) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HttpSessionContext getSessionContext() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Object getAttribute(String name) {
    return sessionMap.get(name);
  }

  @Override
  public Object getValue(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Enumeration<String> getAttributeNames() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String[] getValueNames() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setAttribute(String name, Object value) {
    sessionMap.put(name, value);
  }

  @Override
  public void putValue(String name, Object value) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void removeAttribute(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void removeValue(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void invalidate() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isNew() {
    throw new UnsupportedOperationException();
  }

  public UserSession getUserSession() {
    return (UserSession) getAttribute("user_session");
  }

  public ClientSession getClientSession() {
    return (ClientSession) getAttribute("client_session");
  }
}
