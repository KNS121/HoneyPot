package parser

type LogEntry interface {
	IsLogin() bool
	GetUsername() string
	GetTime() string
}

type Alert struct {
	Type       string `json:"type"`
	Date       string `json:"date"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	Action     string `json:"action"`
	Status     string `json:"status,omitempty"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	Count      int    `json:"count,omitempty"`
}