package main

import (
	"context"
	"fmt"

	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
)

type DBConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
}

func newDatabaseClient(config *DBConfig) (*ent.Client, error) {
	client, err := ent.Open("sqlite3", fmt.Sprintf("file:%s?_fk=1", config.Path))
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to sqlite: %v", err)
	}

	if err = client.Schema.Create(context.Background()); err != nil {
		return nil, fmt.Errorf("failed creating schema resources: %v", err)
	}
	return client, nil
}
