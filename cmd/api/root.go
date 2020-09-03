package main

import (
	"log"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	config  *Config
	csAPI   *API
	rootCmd = &cobra.Command{
		Use:   "csapi",
		Short: "csapi allows you to launch or manage crowdsec API",
		Example: `
- csapi run
- csapi run --config <path_to_config_file>
- csapi generate api_key
- csapi watcher list
- csapi watcher accept
- csapi watcher reject
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			log.Printf("Pre run config : %+v", config.DB)

			csAPI, err = newAPI(config)
			if err != nil {
				return err
			}
			return nil
		},
	}
)

func initConfig() {
	var err error

	if cfgFile == "" {
		log.Fatalf("please provide a configuration file with -c")
	}
	config, err = newConfig(cfgFile)
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Printf("Configuration : %+v", config.DB)
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "./config.yaml", "path to crowdsec config file")
	rootCmd.AddCommand(NewRunCommand())
}
