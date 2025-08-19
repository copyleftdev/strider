package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zuub-code/strider/internal/app"
	"github.com/zuub-code/strider/internal/config"
	"github.com/zuub-code/strider/pkg/logger"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfgFile string

	rootCmd := &cobra.Command{
		Use:   "strider",
		Short: "STRIDER - Expert-Level Security Analysis Platform",
		Long: `STRIDER is a sophisticated, production-ready security analysis platform 
that combines advanced web crawling, intelligent network capture, static security 
analysis, and AI-powered risk assessment using local Ollama models.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return config.InitConfig(cfgFile)
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.strider.yaml)")
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug logging")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json|text)")

	// Add subcommands
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newConfigCmd())

	return rootCmd
}

func newScanCmd() *cobra.Command {
	var opts app.ScanOptions

	cmd := &cobra.Command{
		Use:   "scan [URL]",
		Short: "Perform security analysis scan",
		Long: `Crawl and analyze a web application for security vulnerabilities.
Supports static analysis, dynamic testing, and AI-powered risk assessment.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.RootURL = args[0]

			// Initialize logger
			log := logger.New(logger.Config{
				Level:  logger.InfoLevel,
				Format: logger.JSONFormat,
			})

			// Create and run application
			application, err := app.New(opts, log)
			if err != nil {
				return fmt.Errorf("failed to create application: %w", err)
			}

			return application.Run(cmd.Context())
		},
	}

	// Crawl configuration
	cmd.Flags().IntVar(&opts.Concurrency, "concurrency", 3, "number of concurrent workers")
	cmd.Flags().IntVar(&opts.MaxPages, "max-pages", 100, "maximum pages to crawl")
	cmd.Flags().IntVar(&opts.MaxDepth, "max-depth", 5, "maximum crawl depth")
	cmd.Flags().DurationVar(&opts.RequestTimeout, "request-timeout", 30000000000, "request timeout")
	cmd.Flags().DurationVar(&opts.IdleTimeout, "idle-timeout", 2000000000, "network idle timeout")

	// Analysis configuration
	cmd.Flags().BoolVar(&opts.AllowThirdParty, "allow-third-party", false, "allow third-party domain crawling")
	cmd.Flags().Int64Var(&opts.MaxBodySize, "max-body-kb", 256, "maximum response body size in KB")
	cmd.Flags().BoolVar(&opts.EnableJavaScript, "enable-js", true, "enable JavaScript execution")
	cmd.Flags().BoolVar(&opts.EnableImages, "enable-images", false, "enable image loading")

	// AI configuration
	cmd.Flags().StringVar(&opts.OllamaModel, "ollama-model", "llama3.1:8b", "Ollama model for AI analysis")
	cmd.Flags().BoolVar(&opts.EnableAI, "enable-ai", true, "enable AI-powered analysis")

	// Output configuration
	cmd.Flags().StringVar(&opts.OutputDir, "output", "./output", "output directory")
	cmd.Flags().BoolVar(&opts.GenerateSARIF, "sarif", true, "generate SARIF output")
	cmd.Flags().BoolVar(&opts.GenerateJSON, "json", true, "generate JSON output")
	cmd.Flags().BoolVar(&opts.GenerateMarkdown, "markdown", true, "generate Markdown report")

	// Advanced options
	cmd.Flags().BoolVar(&opts.RespectRobots, "respect-robots", true, "respect robots.txt")
	cmd.Flags().BoolVar(&opts.EnableStealth, "stealth", false, "enable stealth mode")
	cmd.Flags().BoolVar(&opts.FastScan, "fast-scan", false, "enable fast scan mode")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("STRIDER %s\n", version)
			fmt.Printf("Commit: %s\n", commit)
			fmt.Printf("Built: %s\n", date)
		},
	}
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize default configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return config.InitDefaultConfig()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return config.ValidateConfig()
		},
	})

	return cmd
}
