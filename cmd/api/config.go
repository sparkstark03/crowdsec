package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Config struct {
	filePath string
	API      *APIConfig `yaml:"api"`
	DB       *DBConfig  `yaml:"db"`
}

func newConfig(filepath string) (*Config, error) {
	newConfig := &Config{
		filePath: filepath,
	}
	rcfg, err := ioutil.ReadFile(filepath)
	if err != nil {
		return newConfig, fmt.Errorf("read '%s' : %s", filepath, err)
	}
	if err := yaml.UnmarshalStrict(rcfg, newConfig); err != nil {
		return newConfig, fmt.Errorf("parse '%s' : %s", filepath, err)
	}
	return newConfig, nil
}
