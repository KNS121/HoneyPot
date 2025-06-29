package parser

type Alert struct {
	Type           string `json:"type"`
	Date           string `json:"date"`
	RemoteAddr     string `json:"remote_addr"`
	Action         string `json:"action"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	AuthStatus     string `json:"auth_status"`
	Count          int    `json:"count,omitempty"`
	CommonPassword string `json:"common_password,omitempty"`
}

type LogEntry interface {
	IsLogin() bool
	GetUsername() string
	GetTime() string
}