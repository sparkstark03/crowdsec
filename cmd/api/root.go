package main

import (
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	config  *csconfig.CrowdSec
	csAPI   *apiserver.APIServer
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

			csAPI, err = apiserver.NewServer(config)
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
	config, err = csconfig.NewCrowdSecConfig(cfgFile)
	if err != nil {
		log.Fatalf(err.Error())
	}

}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "../../config/config.yaml", "path to crowdsec config file")
	rootCmd.AddCommand(NewRunCommand())
	rootCmd.AddCommand(NewGenerateCommand())
}
