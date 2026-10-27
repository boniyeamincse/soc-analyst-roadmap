# Container Logging & Runtime Security — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Linux Logs](linuxlog.md) · [Processes →](Processes.md)

> Goal: Master the telemetry, logging pipelines, attack vectors, and runtime threat detection for Docker containers and Kubernetes clusters.
> Related notes: [linuxlog.md](linuxlog.md); [Linux.md](Linux.md); [Processes.md](Processes.md); [04 - Security Monitoring/Logs.md](../04%20-%20Security%20Monitoring/Logs.md).

---

## 0. How to use this note

1. §1–§2: Container internals vs VMs; Linux primitives (Namespaces, cgroups, seccomp, AppArmor).
2. §3–§4: Docker logging drivers and container telemetry collection mechanisms.
3. §5–§6: Kubernetes architecture, Control Plane logging, and Kube-Audit log analysis.
4. §7–§9: Container attack techniques (breakouts, privilege escalation, crypto-mining) and runtime detection with Falco.
5. §10–§12: SIEM queries, incident triage playbook, self-test questions, and revision checklist.

---

## 1. Containers vs Virtual Machines: Core Primitives

Containers are not lightweight virtual machines; they are **isolated Linux processes sharing the host kernel**.

```
[Virtual Machine]                          [Container]
┌────────────────────────┐         ┌────────────────────────┐
│ App + Binaries / Libs  │         │ App + Binaries / Libs  │
├────────────────────────┤         ├────────────────────────┤
│ Guest OS (Own Kernel)  │         │ Isolated Namespace/cgroup│
├────────────────────────┤         ├────────────────────────┤
│ Hypervisor (KVM/ESXi)  │         │ Container Runtime      │
├────────────────────────┤         ├────────────────────────┤
│ Host Hardware / OS     │         │ Shared Host OS Kernel  │
└────────────────────────┘         └────────────────────────┘
```

### The 4 Linux Kernel Primitives Underneath Containers
1. **Namespaces:** Provide resource isolation (what the container can *see*):
   - `pid` (process tree), `net` (routing/interfaces), `mnt` (filesystem mounts), `ipc` (inter-process comms), `uts` (hostname), `user` (UID/GID mapping).
2. **Control Groups (cgroups):** Resource limits (what the container can *use* — CPU, RAM, disk I/O).
3. **Seccomp (Secure Computing Mode):** Filters which system calls (`syscalls`) a containerized process can invoke.
4. **AppArmor / SELinux:** Mandatory Access Control (MAC) policies restricting file, network, and execution permissions.

---

## 2. Docker Telemetry & Logging Architecture

### 2.1 Where do Docker logs go?
By default, Docker captures stdout and stderr from running containers using logging drivers:

| Driver | Description | Default Path / Destination |
|---|---|---|
| `json-file` (default) | Logs formatted as JSON lines. | `/var/lib/docker/containers/<container-id>/<container-id>-json.log` |
| `journald` | Directs container output into systemd journal. | Queryable via `journalctl -u docker` or `CONTAINER_NAME=<name>`. |
| `syslog` | Forwards stdout/stderr to local or remote syslog server. | Centralized syslog collector / SIEM forwarder. |
| `fluentd` / `splunk` | Ships logs directly to external collectors via TCP/TLS. | Centralized enterprise pipeline. |

### 2.2 Docker Daemon & Host Logs
- **Docker Daemon Log:** Records container lifecycle events (creates, starts, terminates, crashes):
  - Systems using systemd: `journalctl -u docker.service`
  - Linux log file: `/var/log/docker.log`
- **Docker Event Stream:** Real-time event auditing:
  ```bash
  docker events --since '1h' --filter 'event=die' --filter 'event=create'
  ```

---

## 3. Kubernetes Logging Architecture

Kubernetes clusters generate three distinct tiers of security telemetry:

```
[Cluster Architecture]
   ├── 1. Node & Kubelet Logs (/var/log/messages, journalctl -u kubelet)
   ├── 2. Container Application Logs (/var/log/pods/<namespace>_<pod>_<uid>/...)
   └── 3. Kubernetes API Audit Logs (Control Plane: Who did what in the cluster?)
```

### 3.1 Kubernetes API Audit Logs (`kube-audit`)
The Kube-Audit log is the single most critical data source for detecting control plane compromise:
- **Stages:** `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`.
- **Audit Levels:**
  - `None`: Do not log.
  - `Metadata`: Request metadata (user, timestamp, resource, verb, namespace).
  - `Request`: Metadata + request body.
  - `RequestResponse`: Full request and response body.

```yaml
# Recommended Security Audit Policy Snippet (/etc/kubernetes/audit-policy.yaml)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Alert on changes to ClusterRoleBindings or Roles (Privilege Escalation)
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
  # Log Secret access attempts
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
```

---

## 4. Container Attacks & Breakout Techniques

### 4.1 Privileged Container Abuse (`--privileged`)
- Running a container with `--privileged` disables all seccomp profiles, grants all Linux capabilities (`CAP_SYS_ADMIN`), and exposes all host devices.
- **Breakout Mechanism:** Attacker inside container mounts the host root disk directly:
  ```bash
  # Inside a privileged container:
  mkdir /host_root
  mount /dev/sda1 /host_root
  chroot /host_root  # Instant root on the underlying host!
  ```

### 4.2 Docker Socket Exposure (`docker.sock`)
- Mounting `/var/run/docker.sock` inside a container allows the container to issue API commands directly to the host Docker daemon.
- **Breakout Mechanism:** Attacker inside container spawns a new privileged sibling container mounting the host root:
  ```bash
  docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
  ```

### 4.3 Kernel Exploits & Capability Abuse
- `CAP_SYS_PTRACE`: Allows an attacker to attach to and inject code into host processes running outside the container.
- `CAP_NET_ADMIN`: Allows packet sniffing, routing table tampering, and network spoofing across the entire node.

---

## 5. Runtime Security & Detection with Falco

[Falco](https://falco.org/) is the open-source de facto runtime security standard for Linux containers and Kubernetes, operating at the kernel level via **eBPF** or a kernel module.

### 5.1 Falco Rule Anatomy
Falco intercepts kernel system calls (`execve`, `open`, `connect`) in real time:

```yaml
# Falco Rule: Detect Interactive Bash/Sh Execution inside a Container
- rule: Terminal Shell in Container
  desc: A shell was spawned by a container with an attached terminal
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
  output: >
    Shell spawned in container (user=%user.name container_id=%container.id
    container_name=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

```yaml
# Falco Rule: Detect Sensitive Host Directory Mount in Container
- rule: Sensitive Host Directory Mounted in Container
  desc: Detects a container mounting host root, /etc, or /var/run/docker.sock
  condition: >
    container.id != host and
    (container.mounts contains "/etc" or
     container.mounts contains "/var/run/docker.sock" or
     container.mounts contains "/")
  output: "Sensitive host path mounted (container=%container.name mount=%container.mounts)"
  priority: CRITICAL
```

---

## 6. SIEM Detection Queries

```spl
# Splunk: Detect Privileged Pod or Secret Access in Kubernetes Audit Logs
index=kube_audit verb IN ("create", "patch") "objectRef.resource"="pods"
| search "requestObject.spec.containers{}.securityContext.privileged"=true
| table _time, user.username, sourceIPs{}, objectRef.namespace, objectRef.name
```

```kusto
// KQL: Detect ClusterRoleBinding assigned to "cluster-admin" (Privilege Escalation)
KubeAudit
| where Verb == "create"
| where ObjectRef.Resource == "clusterrolebindings"
| extend RoleRef = tostring(parse_json(RequestObject).roleRef.name)
| extend Subject = tostring(parse_json(RequestObject).subjects[0].name)
| where RoleRef == "cluster-admin"
| project TimeGenerated, User.Username, SourceIps, ObjectRef.Name, RoleRef, Subject
```

---

## 7. Container Incident Triage Playbook

```
Alert: Falco Shell Spawned in Production Web Container / Anomalous Kube-Audit Call
   │
   ├─ 1. Determine Scope & Environment
   │     • Extract Container ID, Pod Name, Namespace, and Node Hostname.
   │     • Check workload role: Is this a stateless front-end web server or an internal DB worker?
   │
   ├─ 2. Inspect Execution Lineage
   │     • Was the shell (`/bin/sh`) spawned by the web application process (e.g. `nginx`, `java`, `node`)?
   │     • If spawned by web process: Immediate indicator of Remote Code Execution (RCE) / Web Shell!
   │
   ├─ 3. Check for Escape Attempts
   │     • Check if container was started with `privileged: true` or mounted `/var/run/docker.sock`.
   │     • Check network connections from container IP to node metadata (`169.254.169.254`) or internal Kube-DNS.
   │
   └─ 4. Immediate Containment
         • Do NOT simply delete the pod immediately (destroys memory and disk evidence!).
         • Step A: Disconnect pod network via Kubernetes NetworkPolicy (isolate pod).
         • Step B: Take container commit snapshot (`docker commit <id> preserved_evidence:tag`).
         • Step C: Evict or terminate pod after memory/snapshot preservation.
```

---

## 8. Hardening Guidelines

1. **Read-Only Root Filesystem:** Deploy containers with `readOnlyRootFilesystem: true`. Forces attackers to write only to ephemeral `/tmp` or fails malware droppers outright.
2. **Drop All Capabilities:** Explicitly drop all Linux capabilities and add only the exact required one:
   ```yaml
   securityContext:
     capabilities:
       drop: ["ALL"]
       add: ["NET_BIND_SERVICE"]
   ```
3. **Never Run as Root:** Enforce non-root execution (`runAsNonRoot: true`, `runAsUser: 10001`).
4. **Never Mount Docker Socket:** Prohibit mounting `/var/run/docker.sock` in non-administrative pods.
5. **Enforce Admission Controllers:** Use OPA Gatekeeper or Kyverno to reject pods requesting privileged access.

---

## 9. Hands-on Labs

1. **Docker Logging Drivers:** Run an Nginx container using `--log-driver=journald` and locate the logs using `journalctl`.
2. **Breakout Simulation:** In an isolated test VM, run a container with `-v /:/host` and observe what telemetry is generated in host audit logs.
3. **Falco Deployment:** Install Falco via Helm or binary on a test Linux VM; trigger an interactive shell inside a container and observe the alert.
4. **Kube-Audit Policy Lab:** Configure `/etc/kubernetes/audit-policy.yaml` on Minikube; query audit logs for secret enumeration.

---

## 10. Self-test questions

1. What are the four Linux kernel primitives that make containerization possible?
2. Why is running a container with the `--privileged` flag dangerous from a security standpoint?
3. How can an attacker who compromises a container escape to the host if `/var/run/docker.sock` is mounted?
4. What is the difference between container application logs (stdout/stderr) and Kubernetes API audit logs?
5. What mechanism does Falco use to inspect container process activity in real time?
6. Why shouldn't a SOC analyst immediately delete a compromised pod during an active investigation?

---

## 11. One-page revision checklist

- [ ] Linux primitives: Namespaces (isolation), cgroups (resource limits), seccomp (syscall filtering), AppArmor (MAC).
- [ ] Container logs: Default `/var/lib/docker/containers/<id>/<id>-json.log`, stdout/stderr capture.
- [ ] Kube-Audit: API server audit logs (`/etc/kubernetes/audit-policy.yaml`), records verbs (`create`, `get`, `delete`) and RBAC changes.
- [ ] Breakout risks: `--privileged` flag, `/var/run/docker.sock` mount, `CAP_SYS_ADMIN`, host path volume mounts (`/etc`, `/`).
- [ ] Falco: Kernel-level runtime security (eBPF), alerts on shell execution in containers, binary drops, sensitive mounts.
- [ ] Containment: NetworkPolicy isolation, `docker commit` evidence snapshot, node quarantine before pod deletion.
- [ ] Hardening: `readOnlyRootFilesystem: true`, `drop: ["ALL"]` capabilities, `runAsNonRoot: true`.

---

> **Navigation:** [Roadmap index](../README.md) · [← Linux Logs](linuxlog.md) · [Processes →](Processes.md)
