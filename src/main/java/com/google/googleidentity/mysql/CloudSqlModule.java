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

package com.google.googleidentity.mysql;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.sql.DataSource;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * Create connections to cloud sql follow
 * https://github.com/GoogleCloudPlatform/java-docs-samples/tree/master/cloud-sql/mysql/servlet
 */
public class CloudSqlModule extends AbstractModule {
  private static final String CLOUD_SQL_CONNECTION_NAME =
      System.getenv("CLOUD_SQL_CONNECTION_NAME");
  private static final String DB_USER = System.getenv("DB_USER");
  private static final String DB_PASS = System.getenv("DB_PASS");
  private static final String DB_NAME = System.getenv("DB_NAME");

  private static final Logger log = Logger.getLogger("MySqlModule");

  @Override
  public void configure() {}

  @Provides
  @Singleton
  public DataSource createConnectionPool() {

    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(String.format("jdbc:mysql:///%s", DB_NAME));
    config.setUsername(DB_USER);
    config.setPassword(DB_PASS);

    config.addDataSourceProperty("socketFactory", "com.google.cloud.sql.mysql.SocketFactory");
    config.addDataSourceProperty("cloudSqlInstance", CLOUD_SQL_CONNECTION_NAME);

    config.setMaximumPoolSize(20);

    config.setMinimumIdle(20);

    config.setConnectionTimeout(10000);

    config.setIdleTimeout(600000);

    config.setMaxLifetime(1800000);

    DataSource pool = new HikariDataSource(config);

    if (("true").equals(System.getenv("CLEAR_TABLES"))) {
      try {
        dropTables(pool);
      } catch (SQLException exception) {
        log.log(Level.INFO, "Drop tables error.", exception);
      }

      try {
        createTables(pool);
      } catch (SQLException exception) {
        log.log(Level.INFO, "Create tables error.", exception);
      }
    }
    return pool;
  }

  private void dropTables(DataSource pool) throws SQLException {
    Connection conn = pool.getConnection();
    String stmt = "DROP TABLE IF EXISTS user, client, code, access_token, refresh_token;";
    PreparedStatement statement = conn.prepareStatement(stmt);
    statement.execute();
    statement.close();
    conn.close();
  }

  private void createTables(DataSource pool) throws SQLException {
    Connection conn = pool.getConnection();

    String stmt =
        "CREATE TABLE user "
            + "(username VARCHAR(255) NOT NULL, "
            + "password VARCHAR(255), "
            + "email VARCHAR(255), "
            + "google_account_id VARCHAR(255), "
            + "PRIMARY KEY (username));";
    PreparedStatement statement = conn.prepareStatement(stmt);
    statement.execute();

    stmt =
        "CREATE TABLE client "
            + "(client_id VARCHAR(255) NOT NULL, "
            + "secret VARCHAR(2047), "
            + "grant_types VARCHAR(255), "
            + "is_scoped BOOLEAN,"
            + "scopes VARCHAR(2047), "
            + "redirect_uris VARCHAR(2047),"
            + "risc_uri VARCHAR(255),"
            + "risc_aud VARCHAR(255),"
            + "PRIMARY KEY (client_id));";
    statement = conn.prepareStatement(stmt);
    statement.execute();

    stmt =
        "CREATE TABLE code "
            + "(code VARCHAR(255) NOT NULL, "
            + "request VARBINARY(2047), "
            + "PRIMARY KEY (code));";
    statement = conn.prepareStatement(stmt);
    statement.execute();

    stmt =
        "CREATE TABLE access_token "
            + "(access_token VARCHAR(255) NOT NULL, "
            + "client_id VARCHAR(255) NOT NULL, "
            + "username VARCHAR(255) NOT NULL, "
            + "is_scoped BOOLEAN,"
            + "scopes VARCHAR(2047), "
            + "expired_time BIGINT, "
            + "refresh_token VARCHAR(255), "
            + "PRIMARY KEY (access_token));";
    statement = conn.prepareStatement(stmt);
    statement.execute();

    stmt =
        "CREATE TABLE refresh_token "
            + "(refresh_token VARCHAR(255) NOT NULL, "
            + "client_id VARCHAR(255) NOT NULL, "
            + "username VARCHAR(255) NOT NULL, "
            + "is_scoped BOOLEAN,"
            + "scopes VARCHAR(2047), "
            + "PRIMARY KEY (username, client_id));";
    statement = conn.prepareStatement(stmt);
    statement.execute();
    statement.close();
    conn.close();
  }
}
