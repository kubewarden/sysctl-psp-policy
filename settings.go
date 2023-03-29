package main

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	easyjson "github.com/mailru/easyjson"

	"fmt"
	"strings"
)

type Settings struct {
	AllowedUnsafeSysctls mapset.Set[string] `json:"allowedUnsafeSysctls"`
	ForbiddenSysctls     mapset.Set[string] `json:"forbiddenSysctls"`
}

func NewSettingsFromRaw(rawSettings *RawSettings) (Settings, error) {
	allowedUnsafeSysctls := mapset.NewThreadUnsafeSet(rawSettings.AllowedUnsafeSysctls...)
	forbiddenSysctls := mapset.NewThreadUnsafeSet(rawSettings.ForbiddenSysctls...)

	return Settings{
		AllowedUnsafeSysctls: allowedUnsafeSysctls,
		ForbiddenSysctls:     forbiddenSysctls,
	}, nil
}

// Builds a new Settings instance starting from a validation
// request payload:
//
//	{
//	   "request": ...,
//	   "settings": {
//	      "allowedUnsafeSysctls": [...],
//	      "forbiddenSysctls": [...]
//	   }
//	}
func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	settingsJson := gjson.GetBytes(payload, "settings")

	rawSettings := RawSettings{}
	err := easyjson.Unmarshal([]byte(settingsJson.Raw), &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings)
}

// Builds a new Settings instance starting from a Settings
// payload:
//
//	{
//	   "allowedUnsafeSysctls": [...],
//	   "forbiddenSysctls": [...]
//	}
func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	rawSettings := RawSettings{}
	err := easyjson.Unmarshal(payload, &rawSettings)
	if err != nil {
		return Settings{}, err
	}

	return NewSettingsFromRaw(&rawSettings)
}

func (s *Settings) Valid() (bool, error) {

	for _, elem := range s.AllowedUnsafeSysctls.ToSlice() {
		if strings.Contains(elem, "*") {
			return false,
				fmt.Errorf("allowedUnsafeSysctls doesn't accept patterns with `*`")
		}
	}

	for _, elem := range s.ForbiddenSysctls.ToSlice() {
		if strings.Contains(elem, "*") &&
			!strings.HasSuffix(elem, "*") {
			return false,
				fmt.Errorf("forbiddenSysctls only accepts patterns with `*` as suffix")
		}
	}

	allowedAndForbidden := s.AllowedUnsafeSysctls.Intersect(s.ForbiddenSysctls)
	if allowedAndForbidden.Cardinality() != 0 {
		return false,
			fmt.Errorf("these sysctls cannot be allowed and forbidden at the same time: %s",
				strings.Join(allowedAndForbidden.ToSlice(), ","),
			)
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
