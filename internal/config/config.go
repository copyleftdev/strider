package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server ServerConfig `mapstructure:"server"`

	// Crawler configuration
	Crawler CrawlerConfig `mapstructure:"crawler"`

	// Analysis configuration
	Analysis AnalysisConfig `mapstructure:"analysis"`

	// AI configuration
	AI AIConfig `mapstructure:"ai"`

	// Storage configuration
	Storage StorageConfig `mapstructure:"storage"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`

	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics"`
}

type ServerConfig struct {
	Port    int    `mapstructure:"port"`
	Host    string `mapstructure:"host"`
	Timeout int    `mapstructure:"timeout"`
}

type CrawlerConfig struct {
	DefaultConcurrency int    `mapstructure:"default_concurrency"`
	DefaultMaxPages    int    `mapstructure:"default_max_pages"`
	DefaultMaxDepth    int    `mapstructure:"default_max_depth"`
	DefaultTimeout     int    `mapstructure:"default_timeout"`
	UserAgent          string `mapstructure:"user_agent"`
	EnableStealth      bool   `mapstructure:"enable_stealth"`
}

type AnalysisConfig struct {
	EnableAllRules bool     `mapstructure:"enable_all_rules"`
	DisabledRules  []string `mapstructure:"disabled_rules"`
	MaxWorkers     int      `mapstructure:"max_workers"`
	CacheSize      int      `mapstructure:"cache_size"`
}

type AIConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	BaseURL      string  `mapstructure:"base_url"`
	DefaultModel string  `mapstructure:"default_model"`
	Temperature  float32 `mapstructure:"temperature"`
	MaxTokens    int     `mapstructure:"max_tokens"`
	Timeout      int     `mapstructure:"timeout"`
}

type StorageConfig struct {
	Type         string `mapstructure:"type"`
	DatabasePath string `mapstructure:"database_path"`
	MaxConns     int    `mapstructure:"max_connections"`
	Timeout      int    `mapstructure:"timeout"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    int    `mapstructure:"port"`
	Path    string `mapstructure:"path"`
}

var globalConfig *Config

// InitConfig initializes the configuration
func InitConfig(cfgFile string) error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".strider")
	}

	// Set defaults
	setDefaults()

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("STRIDER")

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal config
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("error unmarshaling config: %w", err)
	}

	globalConfig = &cfg
	return nil
}

// Get returns the global configuration
func Get() *Config {
	if globalConfig == nil {
		// Initialize with defaults if not already initialized
		setDefaults()
		var cfg Config
		viper.Unmarshal(&cfg)
		globalConfig = &cfg
	}
	return globalConfig
}

// InitDefaultConfig creates a default configuration file
func InitDefaultConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, ".strider.yaml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("configuration file already exists at %s", configPath)
	}

	// Create default config content
	defaultConfig := `# STRIDER Configuration File

# Server configuration
server:
  port: 8080
  host: "localhost"
  timeout: 30

# Crawler configuration
crawler:
  default_concurrency: 3
  default_max_pages: 100
  default_max_depth: 5
  default_timeout: 30
  user_agent: "STRIDER/1.0 Security Scanner"
  enable_stealth: false

# Analysis configuration
analysis:
  enable_all_rules: true
  disabled_rules: []
  max_workers: 4
  cache_size: 1000

# AI configuration
ai:
  enabled: true
  base_url: "http://localhost:11434"
  default_model: "llama3.1:8b"
  temperature: 0.1
  max_tokens: 2048
  timeout: 60

# Storage configuration
storage:
  type: "sqlite"
  database_path: "./strider.db"
  max_connections: 10
  timeout: 30

# Logging configuration
logging:
  level: "info"
  format: "json"
  output: "stdout"

# Metrics configuration
metrics:
  enabled: true
  port: 9090
  path: "/metrics"
`

	// Write config file
	if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	fmt.Printf("Default configuration created at %s\n", configPath)
	return nil
}

// ValidateConfig validates the current configuration
func ValidateConfig() error {
	cfg := Get()

	// Validate server config
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	// Validate crawler config
	if cfg.Crawler.DefaultConcurrency <= 0 {
		return fmt.Errorf("invalid crawler concurrency: %d", cfg.Crawler.DefaultConcurrency)
	}

	if cfg.Crawler.DefaultMaxPages <= 0 {
		return fmt.Errorf("invalid crawler max pages: %d", cfg.Crawler.DefaultMaxPages)
	}

	// Validate AI config
	if cfg.AI.Enabled {
		if cfg.AI.BaseURL == "" {
			return fmt.Errorf("AI base URL is required when AI is enabled")
		}
		if cfg.AI.DefaultModel == "" {
			return fmt.Errorf("AI default model is required when AI is enabled")
		}
	}

	// Validate storage config
	if cfg.Storage.Type != "sqlite" {
		return fmt.Errorf("unsupported storage type: %s", cfg.Storage.Type)
	}

	fmt.Println("Configuration is valid")
	return nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.timeout", 30)

	// Crawler defaults
	viper.SetDefault("crawler.default_concurrency", 3)
	viper.SetDefault("crawler.default_max_pages", 100)
	viper.SetDefault("crawler.default_max_depth", 5)
	viper.SetDefault("crawler.default_timeout", 30)
	viper.SetDefault("crawler.user_agent", "STRIDER/1.0 Security Scanner")
	viper.SetDefault("crawler.enable_stealth", false)

	// Analysis defaults
	viper.SetDefault("analysis.enable_all_rules", true)
	viper.SetDefault("analysis.disabled_rules", []string{})
	viper.SetDefault("analysis.max_workers", 4)
	viper.SetDefault("analysis.cache_size", 1000)

	// AI defaults
	viper.SetDefault("ai.enabled", true)
	viper.SetDefault("ai.base_url", "http://localhost:11434")
	viper.SetDefault("ai.default_model", "llama3.1:8b")
	viper.SetDefault("ai.temperature", 0.1)
	viper.SetDefault("ai.max_tokens", 2048)
	viper.SetDefault("ai.timeout", 60)

	// Storage defaults
	viper.SetDefault("storage.type", "sqlite")
	viper.SetDefault("storage.database_path", "./strider.db")
	viper.SetDefault("storage.max_connections", 10)
	viper.SetDefault("storage.timeout", 30)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")

	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.port", 9090)
	viper.SetDefault("metrics.path", "/metrics")
}
