#!/usr/bin/env bats

@test "accept because pod doesn't list any sysctls" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-no-sysctl.json --settings-json \
    '{ "allowedUnsafeSysctls": [], "forbiddenSysctls": [ "kernel.shm_rmid_forced", "net.*" ] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept because sysctls are all on safe list" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-safe-sysctls.json --settings-json '{}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept because net.core.somaxconn is allowed" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-somaxconn.json --settings-json \
    '{ "allowedUnsafeSysctls": ["net.core.somaxconn"], "forbiddenSysctls": ["net.*"] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject because net.* is forbidden" {
  run kwctl run annotated-policy.wasm -r test_data/request-pod-somaxconn.json --settings-json \
    '{ "allowedUnsafeSysctls": [], "forbiddenSysctls": [ "kernel.shm_rmid_forced", "net.*" ] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*sysctl net.core.somaxconn is on the forbidden list.*") -ne 0 ]
}
