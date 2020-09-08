package database

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

type DBConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

func newDatabaseClient(config *DBConfig) (*database.Client, error) {
	client, err := database.Open("sqlite3", fmt.Sprintf("file:%s?_fk=1", config.Path))
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to sqlite: %v", err)
	}

	if err = client.Schema.Create(context.Background()); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %v", err)
	}
	return client, nil
}
