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

package com.google.googleidentity.oauth2.authorizationcode;

import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.inject.Inject;
import com.google.protobuf.InvalidProtocolBufferException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** Jdbc implementation for {@link CodeStore} */
public class JdbcCodeStore implements CodeStore {

  private final DataSource dataSource;

  private final Logger log = Logger.getLogger("JdbcCodeStore");

  @Inject
  public JdbcCodeStore(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public Optional<OAuth2Request> consumeCode(String code) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "SELECT * FROM code WHERE code = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, code);
      result = statement.executeQuery();
      if (result.next()) {
        stmt = "DELETE FROM code WHERE code = ?;";
        statement = conn.prepareStatement(stmt);
        statement.setString(1, code);
        statement.execute();
        Optional<OAuth2Request> client =
            Optional.ofNullable(OAuth2Request.parseFrom(result.getBytes("request")));
        conn.commit();
        return client;
      }
    } catch (SQLException | InvalidProtocolBufferException exception) {
      log.log(Level.INFO, "Consume Code Error.", exception);
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        log.log(Level.INFO, "Roll Back Error.", exception1);
      }
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          log.log(Level.INFO, "Close result error.", exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception2) {
          log.log(Level.INFO, "Close stmt error.", exception2);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception3) {
          log.log(Level.INFO, "Close conn error.", exception3);
        }
      }
    }
    return Optional.empty();
  }

  @Override
  public boolean setCode(String code, OAuth2Request request) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "SELECT * FROM code WHERE code = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, code);
      result = statement.executeQuery();
      if (!result.next()) {
        stmt = "INSERT INTO code VALUES(?, ?);";
        statement = conn.prepareStatement(stmt);
        statement.setString(1, code);
        statement.setBytes(2, request.toByteArray());
        statement.execute();
        conn.commit();
        return true;
      } else {
        return false;
      }
    } catch (SQLException exception) {
      log.log(Level.INFO, "Set Code Error.", exception);
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        log.log(Level.INFO, "Roll Back Error.", exception1);
      }
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          log.log(Level.INFO, "Close result error.", exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception2) {
          log.log(Level.INFO, "Close stmt error.", exception2);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception3) {
          log.log(Level.INFO, "Close conn error.", exception3);
        }
      }
    }
    return false;
  }

  @Override
  public void reset() {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "DELETE FROM code;";
      statement = conn.prepareStatement(stmt);
      statement.execute();
      conn.commit();
    } catch (SQLException exception) {
      log.log(Level.INFO, "Reset Error.", exception);
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        log.log(Level.INFO, "Roll Back Error.", exception1);
      }
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          log.log(Level.INFO, "Close result error.", exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception2) {
          log.log(Level.INFO, "Close stmt error.", exception2);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception3) {
          log.log(Level.INFO, "Close conn error.", exception3);
        }
      }
    }
  }
}
