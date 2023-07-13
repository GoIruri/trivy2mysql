package cmd

import (
	"context"
	trivylog "github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/cobra"
	"os"
	"trivy2mysql/config"
	"trivy2mysql/internal"
)

var (
	quiet                    bool
	light                    bool
	skipInit                 bool
	skipUpdate               bool
	vulnerabilitiesTableName string
	adivisoryTableName       string
	sources                  []string
)

var rootCmd = &cobra.Command{
	Use:          "trivy2mysql [DSN]",
	SilenceUsage: true,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		dsn := args[0]
		if err := internal.FetchTrivyDB(ctx, config.CacheDir, light, quiet, skipUpdate); err != nil {
			return err
		}
		if !skipInit {
			if err := internal.InitDB(ctx, dsn, vulnerabilitiesTableName, adivisoryTableName); err != nil {
				return err
			}
		}
		if err := internal.UpdateDB(ctx, config.CacheDir, dsn, vulnerabilitiesTableName, adivisoryTableName, sources); err != nil {
			return err
		}

		return nil
	},
}

func Execute() {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	if err := trivylog.InitLogger(false, true); err != nil {
		rootCmd.PrintErrln(err)
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&light, "light", "", false, "light")
	quiet = false
	rootCmd.Flags().BoolVarP(&skipInit, "skip-init-db", "", false, "skip initializing target datasource")
	rootCmd.Flags().BoolVarP(&skipUpdate, "skip-update", "", false, "skip updating Trivy DB")
	rootCmd.Flags().StringVarP(&vulnerabilitiesTableName, "vulnerabilities-table-name", "", "vulnerabilities", "Vulnerabilities Table Name")
	rootCmd.Flags().StringVarP(&adivisoryTableName, "advisory-table-name", "", "vulnerability_advisories", "Vulnerability Advisories Table Name")
	rootCmd.Flags().StringArrayVarP(&sources, "source", "", nil, "Vulnerability Source (supporting regexp)")
}
