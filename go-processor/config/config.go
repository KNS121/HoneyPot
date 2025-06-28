package config

type Config struct {
    ClickhouseHost string
    ClickhouseUser string
    ClickhousePass string
    ClickhouseDB   string
    PrometheusPort string
}

func Load() *Config {
    return &Config{
        ClickhouseHost: "clickhouse:9000",
        ClickhouseUser: "default",
        ClickhousePass: "",
        ClickhouseDB:   "honeypot",
        PrometheusPort: "2112",
    }
}