package config

import "os"

type Config struct {
	ProxyURL  string
	WorkerURL string
	DebugMode bool
}

func Load() Config {
	return Config{
		ProxyURL:  getEnv("PROXY_URL", "http://localhost:8080"),
		WorkerURL: getEnv("WORKER_URL", ""),
		DebugMode: getEnv("DEBUG", "false") == "true",
	}
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
