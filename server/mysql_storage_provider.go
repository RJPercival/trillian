// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"database/sql"
	"flag"
	"sync"

	"github.com/golang-migrate/migrate"
	migratedb "github.com/golang-migrate/migrate/database/mysql"
	"github.com/golang/glog"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/mysql"

	// Load MySQL driver
	mysqldriver "github.com/go-sql-driver/mysql"
)

const (
	// Increment this when changing the database schema and provide
	// migration scripts in the location pointed to by schemaMigrationSource
	mysqlSchemaVersion         = 1
	mysqlSchemaMigrationSource = "storage/mysql/schema"
)

var (
	mySQLURI = flag.String("mysql_uri", "test:zaphod@tcp(127.0.0.1:3306)/test", "Connection URI for MySQL database")
	maxConns = flag.Int("mysql_max_conns", 0, "Maximum connections to the database")
	maxIdle  = flag.Int("mysql_max_idle_conns", -1, "Maximum idle database connections in the connection pool")

	mysqlOnce            sync.Once
	mysqlOnceErr         error
	mySQLstorageInstance *mysqlProvider
)

func init() {
	if err := RegisterStorageProvider("mysql", newMySQLStorageProvider); err != nil {
		glog.Fatalf("Failed to register storage provider mysql: %v", err)
	}
}

type mysqlProvider struct {
	db *sql.DB
	mf monitoring.MetricFactory
}

func newMySQLStorageProvider(mf monitoring.MetricFactory) (StorageProvider, error) {
	mysqlOnce.Do(func() {
		var db *sql.DB
		db, mysqlOnceErr = mysql.OpenDB(*mySQLURI)
		if mysqlOnceErr != nil {
			return
		}
		if *maxConns > 0 {
			db.SetMaxOpenConns(*maxConns)
		}
		if *maxIdle >= 0 {
			db.SetMaxIdleConns(*maxIdle)
		}
		mySQLstorageInstance = &mysqlProvider{
			db: db,
			mf: mf,
		}
	})
	if mysqlOnceErr != nil {
		return nil, mysqlOnceErr
	}
	return mySQLstorageInstance, nil
}

func (s *mysqlProvider) Migrate() error {
	// Make a new connection for migration purposes, instead of using s.db,
	// because it requires multi-statement mode to be enabled.
	cfg, err := mysqldriver.ParseDSN(*mySQLURI)
	if err != nil {
		return err
	}
	// Enable multiple statements in one query. This "greatly increases the
	// risk of SQL injections" (https://github.com/go-sql-driver/mysql#multistatements),
	// but allows batch queries and is required by golang-migrate
	// (https://godoc.org/github.com/golang-migrate/migrate/database/mysql#WithInstance),
	// which we use for applying database schema changes.
	cfg.MultiStatements = true

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}
	dbDriver, err := migratedb.WithInstance(db, &migratedb.Config{})
	if err != nil {
		return err
	}
	migration, err := migrate.NewWithDatabaseInstance(mysqlSchemaMigrationSource, "MySQL Storage", dbDriver)
	if err != nil {
		return err
	}
	return migration.Migrate(mysqlSchemaVersion)
}

func (s *mysqlProvider) LogStorage() storage.LogStorage {
	return mysql.NewLogStorage(s.db, s.mf)
}

func (s *mysqlProvider) MapStorage() storage.MapStorage {
	return mysql.NewMapStorage(s.db)
}

func (s *mysqlProvider) AdminStorage() storage.AdminStorage {
	return mysql.NewAdminStorage(s.db)
}

func (s *mysqlProvider) Close() error {
	return s.db.Close()
}
