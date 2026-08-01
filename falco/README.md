# Falco Rules

Runtime security rules for [Falco](https://falco.org/) targeting Kubernetes and Linux container environments. These YAML rule files can be loaded via Falco's `rules_file` configuration directive.

## Coverage

The rules detect privileged-container shells, sensitive hostPath access, Kubernetes service-account token reads, `kubectl exec`, admission-webhook tampering, Docker socket access, mount/namespace abuse, `/proc/self/exe` escape primitives, reverse shells, and container credential-file reads.

Every rule has `Security Team` authorship, a 2026-08-01 date, severity/priority, ATT&CK technique and tactic metadata, and ATT&CK references. The rules require the Falco syscall event source and Kubernetes metadata enrichment where container context is needed.

## Deployment notes

1. Load the files after the upstream Falco macros and lists so fields such as `container.privileged` are available.
2. Test the rules in a non-production cluster; legitimate debugging and platform components can require allowlists.
3. Route `CRITICAL` and `WARNING` output to the incident pipeline with Kubernetes namespace, pod, and workload context.

## References

- [Falco Rules Documentation](https://falco.org/docs/rules/)
- [MITRE ATT&CK](https://attack.mitre.org/)
