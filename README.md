# Kubewarden policy to control sysctls in pods

## Description

Replacement for the Kubernetes Pod Security Policy that controls the usage of
sysctls.

Linux Kernel sysctls are grouped into safe and unsafe sets. A safe sysctl must
be properly isolated between pods on the same node, and are properly namespaced
by the kernel. 

All safe sysctls are enabled by default in Kubernetes.
All unsafe sysctls are disabled by default and must be explicitly allowed on a
per-node or per-pod basis.

As the deprecated analogous Kubernetes PSP, this policy validates which sysctls
can get set in pods by specifying lists of sysctls or sysctl patterns to be
allowed or forbidden. One can then modify the `securityContext` of Pods to make
use of the Sysctls as permitted by this policy.

Remember that pods that specify disabled unsafe sysctls will be scheduled, but
will fail to launch with `sysctlForbidden`.

## Settings

The following settings are accepted:

* `forbiddenSysctls`: List of plain sysctl names or sysctl patterns (which end
  with `*`) to be forbidden. You can forbid a combination of safe and unsafe
  sysctls in the list. To forbid setting any sysctls, use `*` on its own.
* `allowedUnsafeSysctls`: List of plain sysctl names that can be used in Pods.
  `*` cannot be used.

A sysctl cannot be both forbidden and allowed at the same time.

### Example

With this policy deployed and configured as:

```yaml
forbiddenSysctls:
- kernel.*
- net.ipv6.conf.lo.max_addresses
allowedUnsafeSysctls:
- net.core.somaxconn
```

A pod can specify the following Sysctls, that would get permitted:

``` yaml
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-example
spec:
  securityContext:
    sysctls:
    - name: net.core.somaxconn
      value: "1024"
...
```


Yet the following pod will get rejected:

``` yaml
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-example
spec:
  securityContext:
    sysctls:
    - name: kernel.shm_rmid_forced
      value: "0"
    - name: kernel.msgmax
      value: "65536"
...
```
