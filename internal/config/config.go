package config

import "os"

type Config struct {
	ProxyURL  string
	WorkerURL string
	DebugMode bool
}

func Load() Config {
	return Config{
		ProxyURL:  getEnv("NEX_PROXY_URL", "http://localhost:8080"),
		WorkerURL: getEnv("NEX_WORKER_URL", ""),
		DebugMode: getEnv("NEX_DEBUG", "false") == "true",
	}
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
