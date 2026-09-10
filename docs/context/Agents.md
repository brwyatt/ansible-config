# AI Agent Guidelines and Repository Standards

This document outlines the standard operating procedures, style requirements, and critical infrastructure design patterns for development in the `ansible-config` repository. All automated developers and AI agents must adhere to these standards to ensure configuration correctness, style consistency, and reliability across the `home.brwyatt.net` homelab environment.

---

## 1. Ansible Coding Standards & YAML Style

### 1.1 Task Spacing and Grouping
* **No Empty Lines Between Tasks**: In Ansible task files (e.g., `tasks/main.yml`), write tasks back-to-back without blank lines between them.
* **Logical Grouping**: If grouping is required to separate concerns, prefer logical organization patterns:
  * Splitting tasks into dedicated sub-files and using `ansible.builtin.include_tasks`.
  * Grouping related tasks into a `block` with appropriate `when` or `become` statements.
  * Avoid blank lines between tasks even within a block or sub-file unless explicitly necessary for readability (never put blank lines between every single task).

*Correct Style Example:*
```yaml
- name: Create configurations directory
  ansible.builtin.file:
    path: "/etc/myapp"
    state: directory
    mode: '0755'
- name: Deploy application configuration
  ansible.builtin.template:
    src: myapp.conf.j2
    dest: "/etc/myapp/myapp.conf"
    mode: '0644'
  notify: Restart myapp
```

### 1.2 Fully Qualified Collection Names (FQCN)
* **Always use FQCN**: Do not use short module names (e.g., `apt`, `template`, `copy`). Always use their fully qualified collection namespace (e.g., `ansible.builtin.apt`, `ansible.builtin.template`, `ansible.builtin.copy`).

### 1.3 Path Variable Conventions (No Hardcoding)
* **Avoid Hardcoded Home Paths**: Never hardcode absolute home or user directory paths like `/home/home.brwyatt.net/brwyatt/`.
* **Use Variables & Facts**: Construct paths dynamically using variables (e.g., `{{ code_server_user }}`) or Ansible facts (e.g., `{{ ansible_env.HOME }}`) to ensure configurations remain host-agnostic and resilient to user changes.

---

## 2. Secrets & Vaulting Rules

* **Decouple Configuration from Secrets**: All passwords, API tokens, private keys, and sensitive string variables must reside in `secrets.yml` files (located within group or host variables directories, e.g., `inventory/group_vars/<group>/secrets.yml`).
* **Vault Reference**: These variables should be referenced dynamically in the playbooks or configurations rather than inlined in raw, public-ready `main.yml` files.
* **Document Constraints**: When introducing new secret variables, document any formatting or complexity requirements (e.g., minimum character length, restricted characters) using comments or within defaults files.

---

## 3. Systemd Network-Backed Mounts & Boot Ordering

To prevent non-deterministic circular dependency deadlocks during boot (particularly on LXC container start/failovers or unclean host restarts), network-backed storage mounts must conform to strict ordering standards.

### 3.1 The Deadlock Cause
If a systemd mount unit lacks the `_netdev` option, systemd classifies it as a local filesystem and automatically assigns a default ordering of `Before=local-fs.target`. If the mount unit simultaneously defines `After=network-online.target`, a circular boot loop is created (systemd-networkd -> network-online -> mount -> local-fs -> systemd-networkd). This deadlock frequently results in systemd discarding `systemd-networkd` completely, causing boot-time network failures.

### 3.2 Standards for Mount Units
* **The `_netdev` Mandate**: All network or FUSE-based mounts (NFS, CephFS, BindFS, etc.) must include `_netdev` inside their mount options.
* **Target Isolation**:
  * **Do NOT use** `After=remote-fs.target` or `After=local-fs.target` in mount templates.
  * **DO use** `After=network-online.target` and specify `Wants=network-online.target` on the mount unit.
* **Correct Template Pattern (`[Mount]`)**:
  ```ini
  [Unit]
  Description=NFS Mount for Application Data
  After=network-online.target
  Wants=network-online.target

  [Mount]
  What=nfs-server.home.brwyatt.net:/mnt/data
  Where=/mnt/data
  Type=nfs
  Options=defaults,_netdev,x-systemd.mount-timeout=5min

  [Install]
  WantedBy=multi-user.target
  ```

### 3.3 Automount Unit Headers
* **Header Exactness**: Ensure that systemd automount units (`.automount` templates) are configured using the proper systemd header: `[Automount]`. Do not use `[Mount]` headers inside `.automount` files.

---

## 4. Service Maintenance & Handler Orchestration

* **Orchestrate Daemon Reloads**: Any task that modifies systemd unit files (`/etc/systemd/system/*`) or deploys templates for mounts/automounts must notify a handler to perform `daemon_reload: true`.
* **State Preservation**: Ensure services are restarted correctly upon configurations change by attaching proper `notify` hooks for systemd unit restarts, preventing stale daemon runs.
