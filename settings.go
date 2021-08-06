package main

import (
	mapset "github.com/deckarep/golang-set"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"

	"fmt"
	"strings"
)

type Settings struct {
	AllowedUnsafeSysctls mapset.Set `json:"allowedUnsafeSysctls"`
	ForbiddenSysctls     mapset.Set `json:"forbiddenSysctls"`
}

// Builds a new Settings instance starting from a validation
// request payload:
// {
//    "request": ...,
//    "settings": {
//       "allowedUnsafeSysctls": [...],
//       "forbiddenSysctls": [...]
//    }
// }
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	return newSettings(
		payload,
		"settings.allowedUnsafeSysctls",
		"settings.forbiddenSysctls")
}

// Builds a new Settings instance starting from a Settings
// payload:
// {
//    "allowedUnsafeSysctls": [...],
//    "forbiddenSysctls": [...]
// }
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	if !gjson.ValidBytes(payload) {
		return Settings{}, fmt.Errorf("denied JSON payload")
	}

	return newSettings(
		payload,
		"settings.allowedUnsafeSysctls",
		"settings.forbiddenSysctls")
}

func newSettings(payload []byte, paths ...string) (Settings, error) {
	if len(paths) != 2 {
		return Settings{}, fmt.Errorf("wrong number of json paths")
	}

	data := gjson.GetManyBytes(payload, paths...)

	allowedUnsafeSysctls := mapset.NewThreadUnsafeSet()
	data[0].ForEach(func(_, entry gjson.Result) bool {
		allowedUnsafeSysctls.Add(entry.String())
		return true
	})

	forbiddenSysctls := mapset.NewThreadUnsafeSet()
	data[1].ForEach(func(_, entry gjson.Result) bool {
		forbiddenSysctls.Add(entry.String())
		return true
	})

	return Settings{
		AllowedUnsafeSysctls: allowedUnsafeSysctls,
		ForbiddenSysctls:     forbiddenSysctls,
	}, nil
}

func (s *Settings) Valid() (bool, error) {

	for _, elem := range s.AllowedUnsafeSysctls.ToSlice() {
		if strings.Contains(elem.(string), "*") {
			return false,
				fmt.Errorf("allowedUnsafeSysctls doesn't accept patterns with `*`")
		}
	}

	for _, elem := range s.ForbiddenSysctls.ToSlice() {
		if strings.Contains(elem.(string), "*") &&
			!strings.HasSuffix(elem.(string), "*") {
			return false,
				fmt.Errorf("forbiddenSysctls only accepts patterns with `*` as suffix")
		}
	}

	allowedAndForbidden := s.AllowedUnsafeSysctls.Intersect(s.ForbiddenSysctls)
	if allowedAndForbidden.Cardinality() != 0 {
		return false,
			fmt.Errorf("these sysctls cannot be allowed and forbidden at the same time: %v",
				allowedAndForbidden.ToSlice()...)
	}

	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	logger.Info("validating settings")

	settings, err := NewSettingsFromValidateSettingsPayload(payload)
	if err != nil {
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if valid {
		return kubewarden.AcceptSettings()
	}

	logger.Warn("rejecting settings")
	return kubewarden.RejectSettings(
		kubewarden.Message(fmt.Sprintf("provided settings are not valid: %v", err)))
}
