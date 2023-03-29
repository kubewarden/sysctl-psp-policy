package main

type RawSettings struct {
	AllowedUnsafeSysctls []string `json:"allowedUnsafeSysctls"`
	ForbiddenSysctls     []string `json:"forbiddenSysctls"`
}
