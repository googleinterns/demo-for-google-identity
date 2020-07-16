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

package com.google.googleidentity.oauth2.client;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import com.google.googleidentity.oauth2.util.OAuth2Enums;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.sql.DataSource;

public class JdbcClientDetailsService implements ClientDetailsService {

  private final DataSource dataSource;

  private final Logger log = Logger.getLogger("JdbcClientDetailsService");

  @Inject
  JdbcClientDetailsService(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public Optional<ClientDetails> getClientByID(String clientID) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM client " + "WHERE client_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, clientID);
      result = statement.executeQuery();
      if (result.next()) {
        Optional<ClientDetails> client = Optional.ofNullable(buildClientFromJdbcResult(result));
        return client;
      }
    } catch (SQLException exception) {
      log.log(Level.INFO, "Get Client Error.", exception);
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
  public boolean updateClient(ClientDetails client) {
    Connection conn = null;
    PreparedStatement statement = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt =
          "UPDATE client "
              + "SET secret = ?, grant_types = ?, "
              + "is_scoped = ?, scopes = ?, redirect_uris = ? "
              + "risc_uri = ?, risc_aud = ?"
              + "WHERE client_id = ?;";
      statement = conn.prepareStatement(stmt);

      List<String> grantTypes = new ArrayList<>();

      for (OAuth2Enums.GrantType type : client.getGrantTypesList()) {
        grantTypes.add(OAuth2EnumMap.REVERSE_GRANT_TYPE_MAP.get(type));
      }

      statement.setString(1, client.getSecret());
      statement.setString(2, String.join("\t", grantTypes));
      statement.setBoolean(3, client.getIsScoped());
      statement.setString(4, String.join("\t", client.getScopesList()));
      statement.setString(5, String.join("\t", client.getRedirectUrisList()));
      statement.setString(6, client.getRiscUri());
      statement.setString(7, client.getRiscAud());
      statement.setString(8, client.getClientId());

      int count = statement.executeUpdate();
      conn.commit();
      return count == 1;
    } catch (SQLException exception) {
      log.log(Level.INFO, "Update Client Error.", exception);
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        log.log(Level.INFO, "Roll Back Error.", exception1);
      }
    } finally {
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
  public boolean addClient(ClientDetails client) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "SELECT * FROM client WHERE client_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, client.getClientId());
      result = statement.executeQuery();
      if (!result.next()) {
        stmt = "INSERT INTO client VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        statement = conn.prepareStatement(stmt);

        List<String> grantTypes = new ArrayList<>();

        for (OAuth2Enums.GrantType type : client.getGrantTypesList()) {
          grantTypes.add(OAuth2EnumMap.REVERSE_GRANT_TYPE_MAP.get(type));
        }

        statement.setString(1, client.getClientId());
        statement.setString(2, client.getSecret());
        statement.setString(3, String.join("\t", grantTypes));
        statement.setBoolean(4, client.getIsScoped());
        statement.setString(5, String.join("\t", client.getScopesList()));
        statement.setString(6, String.join("\t", client.getRedirectUrisList()));
        statement.setString(7, client.getRiscUri());
        statement.setString(8, client.getRiscAud());

        statement.execute();

        conn.commit();
        return true;
      }
    } catch (SQLException exception) {
      log.log(Level.INFO, "Add Client Error.", exception);
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
  public List<ClientDetails> listClient() {
    List<ClientDetails> list = new LinkedList<>();
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM client;";
      statement = conn.prepareStatement(stmt);
      result = statement.executeQuery();
      while (result.next()) {
        list.add(buildClientFromJdbcResult(result));
      }
    } catch (SQLException exception) {
      log.log(Level.INFO, "List Clients Error.", exception);
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
    return ImmutableList.copyOf(list);
  }

  private ClientDetails buildClientFromJdbcResult(ResultSet result) throws SQLException {
    ClientDetails.Builder builder =
        ClientDetails.newBuilder()
            .setClientId(result.getString("client_id"))
            .setSecret(result.getString("secret"))
            .setIsScoped(result.getBoolean("is_scoped"))
            .setRiscUri(result.getString("risc_uri"))
            .setRiscAud(result.getString("risc_aud"));

    String[] grantTypes = result.getString("grant_types").split("\\s+");

    for (String type : grantTypes) {
      builder.addGrantTypes(OAuth2EnumMap.GRANT_TYPE_MAP.get(type));
    }

    builder.addAllScopes(OAuth2Utils.parseScope(result.getString("scopes")));

    String[] redirectUris = result.getString("redirect_uris").split("\\s+");
    builder.addAllRedirectUris(ImmutableSet.copyOf(redirectUris));

    return builder.build();
  }
}
