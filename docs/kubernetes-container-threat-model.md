# Kubernetes and Container Detection Threat Model

## Scope

Kubernetes audit rules in `sigma/cloud/kubernetes/` and Falco runtime rules in `falco/` address control-plane and workload behavior that can lead to credential theft, workload takeover, or escape to the host.

## Threats and detections

| Threat | ATT&CK | Detection focus |
|---|---|---|
| Privileged workload / host escape | T1611 | Privileged pods, sensitive hostPath mounts, Docker socket mounts, `CAP_SYS_ADMIN`, mount/namespace operations, and `/proc/self/exe` primitives |
| Service account token theft | T1528 | Token-secret requests and in-container token file reads |
| Interactive command execution | T1059.004 | Kubernetes API `exec` requests and `kubectl exec` |
| Admission control removal | T1562.001 | Mutating/validating admission webhook configuration changes |
| Container credential collection | T1003.008 | Reads of `/etc/shadow` and cloud credential files |

## Required telemetry

Enable Kubernetes API audit logging at a level that captures request URIs, verbs, users, source IPs, object references, and request objects. Deploy Falco with syscall capture and Kubernetes metadata enrichment. The runtime rules require container ID, image, process command line, file descriptor path, and privileged-container context.

## Assumptions and limitations

API audit rules identify submitted objects and requests; admission rejection or later policy enforcement can prevent actual execution. Falco runtime detection requires the corresponding syscall visibility and may not observe actions on nodes where the sensor is not deployed. The rules do not replace Pod Security Admission, RBAC least privilege, image signing, or network policies.

## Triage

1. Identify the workload, namespace, service account, owner reference, image digest, and initiating principal.
2. Determine whether the pod was admitted and scheduled; for `exec`, retrieve the command and interactive flags.
3. For host escape indicators, isolate the node/workload and inspect host mounts, capabilities, and process ancestry.
4. For token access, rotate the affected service account credentials and review recent API activity from the token identity.

## Expected false positives

Cluster administration, CNI/CSI plugins, node agents, observability products, and approved break-glass debugging can require host access, privileged pods, or `exec`. Exclusions should use the narrowest namespace, workload identity, image digest, and change-window boundaries.
