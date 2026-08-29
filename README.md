# slawo.ssh_bootstrap

This collection discovers initial SSH credentials from an ordered set of username/password candidates. It runs on the Ansible controller, before Ansible has authenticated to the target.

The action plugin can answer common forced-password-change and create-user prompts. It then verifies real privileged access, installs `sudo` when allowed, provisions one automation user, and optionally disables privileged SSH login behind a timed rollback guard.

## Requirements

- `ansible-core >= 2.18`
- OpenSSH `ssh` client and Python `pexpect` on the controller
- Password or keyboard-interactive SSH authentication on the target

## Example

Store real passwords in Ansible Vault or a secret backend. Use `no_log: true`: fallback credentials are intentionally returned when discovered, and debug sessions can still contain sensitive contextual data even though configured passwords are redacted.

```yaml
---
- name: Discover bootstrap access
  hosts: new_nodes
  gather_facts: false
  tasks:
    - name: Find initial SSH credentials
      slawo.ssh_bootstrap.discover_credentials:
        host: "{{ ansible_host | default(inventory_hostname) }}"
        port: "{{ ansible_port | default(22) }}"
        credentials: "{{ vault_bootstrap_credentials }}"
        onboarding:
          username: automation
          password: "{{ vault_automation_password }}"
          passwordless_sudo: true
        root:
          username: root
          password: "{{ vault_root_password }}"
          login: true
          disable_after_onboarding: false
        install_sudo: true
        return_password: false
        host_key_checking: "yes"
        timeout: 10
        debug: "{{ ssh_bootstrap_debug | default(false) }}"
      register: bootstrap_access
      no_log: true

    - name: Show sanitized SSH sessions when requested
      ansible.builtin.debug:
        var: bootstrap_access.sessions
      when: ssh_bootstrap_debug | default(false) | bool

    - name: Use discovered credentials
      ansible.builtin.set_fact:
        ansible_user: "{{ bootstrap_access.credentials.username }}"
        ansible_password: "{{ bootstrap_access.credentials.password | default(vault_automation_password) }}"
        ansible_become: "{{ bootstrap_access.become.enabled }}"
        ansible_become_method: "{{ bootstrap_access.become.method | default(omit) }}"
        ansible_become_user: "{{ bootstrap_access.become.user }}"
      no_log: true
```

Candidate data:

```yaml
vault_bootstrap_credentials:
  - username: factory-user
    password: REPLACE_IN_VAULT
  - username: root
    password: REPLACE_IN_VAULT
```

## Options

| Option | Required | Default | Description |
|---|---:|---|---|
| `credentials` | no | `[]` | Ordered fallback list of username/password dictionaries. |
| `host` | no | inventory host | Target hostname or address. |
| `port` | no | inventory port or `22` | SSH port. |
| `timeout` | no | `10` | Seconds to wait for each prompt. |
| `host_key_checking` | no | `yes` | `yes` requires a trusted key; `accept-new` trusts only unseen keys. |
| `onboarding.username` | no | | Desired user. Must be supplied with `onboarding.password`. |
| `onboarding.password` | no | | Desired user password. Must be supplied with `onboarding.username`. |
| `onboarding.passwordless_sudo` | no | `true` | Grant passwordless sudo; when false, sudo requires the onboarding password. |
| `root.username` | no | `root` | Preferred privileged account name; UID 0 remains the authority check. |
| `root.password` | no | | Try this privileged password before fallback credentials and set it after privileged login. |
| `root.login` | no | `true` | Permit direct SSH attempts for `root.username`. |
| `root.disable_after_onboarding` | no | `false` | Disable SSH for `root.username` only after onboarding SSH and sudo verification. |
| `install_sudo` | no | `true` | Install sudo with the detected platform package manager when missing. |
| `return_password` | no | `false` | Include preferred credentials' password in the result. Discovered fallback passwords are always returned. |
| `prompt_patterns` | no | built-ins | Named Python regex overrides for unusual appliances. |
| `debug` | no | `false` | Return sanitized per-attempt SSH sessions in `sessions`. |

Any non-username prompt ending in `name:` receives an empty response and do not affect the configured username. Pattern keys are `login_password`, `current_password`, `new_password`, `repeat_password`, `new_username`, `ignored_name`, `permission_denied`, `host_key_error`, and `success`.

## Result and safety

The result provides `credentials` (`username`, `uid`, `is_root`, and conditionally `password`), `become`, `attempts`, and `changed`. With `debug: true`, it also returns redacted first-login `sessions`.

- Pre-populate `known_hosts` where possible. Use `accept-new` only on controlled provisioning networks.
- Probing can trigger account lockout; keep candidate lists short and ordered.
- Vendor prompts vary; test regex overrides on an isolated target.
- Privileged SSH disabling is applied from the verified onboarding user's sudo session. A watchdog restores the previous configuration after 60 seconds unless reconnect and sudo-to-UID0 verification succeed.
- Check mode skips probing because authentication and onboarding can affect security state.

## Validation

```shell
python3 -m unittest discover -s collections/ansible_collections/local/ssh_bootstrap/tests/unit
ansible-galaxy collection build collections/ansible_collections/local/ssh_bootstrap
```

## Tested targets

GitHub Actions runs credential discovery against the distribution-provided
OpenSSH server on these targets:

- Ubuntu 22.04, 24.04, and 26.04 LTS
- Debian 12 LTS and Debian 13 stable
- Fedora 44
- Arch Linux rolling (`archlinux:latest`)
- OpenBSD 7.9 in a QEMU virtual machine

The versioned matrix is intentionally limited to releases in standard or
community-supported maintenance. Ubuntu releases that require an Ubuntu Pro
subscription are not part of the required CI gate. Arch is rolling and has no
LTS release. Armbian onboarding is covered separately using its documented
first-login prompt sequence.
