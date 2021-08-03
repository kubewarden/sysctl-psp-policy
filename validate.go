package main

import (
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set"
	onelog "github.com/francoispqt/onelog"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
)

// getSafeSysctls returns an array with known safe sysctls.
//
// A sysctl is called safe iff:
// - it is namespaced in the container or the pod
// - it is isolated, i.e. has no influence on any other pod on the same node.
//
// A (possibly not up-to-date) list of known safe sysctls can be found at:
// https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
func getSafeSysctls() [4]string {
	return [4]string{
		"kernel.shm_rmid_forced",
		"net.ipv4.ip_local_port_range",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.ping_group_range",
	}
}

func validate(payload []byte) ([]byte, error) {
	settings, err := NewSettingsFromValidationReq(payload)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	logger.Info("validating request")

	if kind := gjson.GetBytes(payload, "request.kind"); kind.String() != "Pod" {
		return kubewarden.RejectRequest(
			kubewarden.Message("object is not of kind Pod: rejecting request"),
			kubewarden.Code(421))
	}

	data := gjson.GetBytes(
		payload,
		"request.spec.securityContext.sysctls")

	if !data.Exists() {
		logger.Warn("pod doesn't specify sysctls: accepting request")
		return kubewarden.AcceptRequest()
	}

	logger.DebugWithFields("validating pod object", func(e onelog.Entry) {
		name := gjson.GetBytes(payload, "request.metadata.name").String()
		namespace := gjson.GetBytes(payload,
			"request.metadata.namespace").String()
		e.String("name", name)
		e.String("namespace", namespace)
	})

	// build set of safe sysctls:
	knownSafeSysctlsArray := getSafeSysctls()
	knownSafeSysctls := mapset.NewThreadUnsafeSet()
	for i := 0; i < len(knownSafeSysctlsArray); i++ {
		knownSafeSysctls.Add(knownSafeSysctlsArray[i])
	}

	// build set of prefixes from patterns of forbidden sysctls:
	globForbiddenSysctls := mapset.NewThreadUnsafeSet()
	it := settings.ForbiddenSysctls.Iterator()
	for elem := range it.C {
		if strings.HasSuffix(elem.(string), "*") {
			globForbiddenSysctls.Add(strings.TrimSuffix(elem.(string), "*"))
		}
	}

	data.ForEach(func(key, value gjson.Result) bool {
		sysctl := gjson.Get(value.String(), "name").String()

		if settings.ForbiddenSysctls.Contains(sysctl) {
			err = fmt.Errorf("sysctl %s is on the forbidden list", sysctl)
			return false // stop iterating
		}

		// if sysctl matches a pattern, it is forbidden:
		it := globForbiddenSysctls.Iterator()
		for elem := range it.C {
			if strings.HasPrefix(sysctl, elem.(string)) {
				err = fmt.Errorf("sysctl %s is on the forbidden list", sysctl)
				return false // stop iterating
			}
		}

		// if sysctl is not on the safe list nor an exception, it is forbidden:
		if !knownSafeSysctls.Contains(sysctl) &&
			!settings.AllowedUnsafeSysctls.Contains(sysctl) {
			err = fmt.Errorf("sysctl %s is not on safe list, nor is in the allowedUnsafeSysctls list",
				sysctl)
			return false // stop iterating
		}
		return true // continue iterating
	})

	if err != nil {
		logger.DebugWithFields("rejecting pod object", func(e onelog.Entry) {
			name := gjson.GetBytes(payload, "request.metadata.name").String()
			namespace := gjson.GetBytes(payload, "request.metadata.namespace").String()
			e.String("name", name)
			e.String("namespace", namespace)
		})

		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.NoCode)
	}

	logger.Info("accepting pod object")
	return kubewarden.AcceptRequest()
}
