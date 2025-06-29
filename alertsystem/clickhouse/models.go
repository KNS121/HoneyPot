package clickhouse

type Alert struct {
	Type           string
	Date           string
	RemoteAddr     string
	Action         string
	Username       string
	Password       string
	AuthStatus     string
	Count          int
	CommonPassword string
}