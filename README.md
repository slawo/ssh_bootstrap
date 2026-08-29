# slawo.ssh_bootstrap

This collection discovers initial SSH credentials from an ordered set of username/password candidates. It runs on the Ansible controller, before Ansible has authenticated to the target.

The action plugin can also answer common forced-password-change and create-user prompts. If the relevant onboarding value is omitted, it sends Ctrl-C and returns the credential that successfully authenticated.

## Requirements

- `ansible-core >= 2.18`
- OpenSSH `ssh` client and Python `pexpect` on the controller
- Password or keyboard-interactive SSH authentication on the target

## Example

Store real passwords in Ansible Vault or a secret backend. The task must use `no_log: true`, because its registered value intentionally contains the successful password.

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
          username: "{{ bootstrap_desired_username | default(omit) }}"
          password: "{{ vault_bootstrap_desired_password | default(omit) }}"
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
        ansible_password: "{{ bootstrap_access.credentials.password }}"
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
| `credentials` | yes | | Ordered list of username/password dictionaries. |
| `host` | no | inventory host | Target hostname or address. |
| `port` | no | inventory port or `22` | SSH port. |
| `timeout` | no | `10` | Seconds to wait for each prompt. |
| `host_key_checking` | no | `yes` | `yes` requires a trusted key; `accept-new` trusts only unseen keys. |
| `onboarding.username` | no | | Value for a create-user prompt. |
| `onboarding.password` | no | | Value for new/repeat-password prompts. |
| `onboarding.user_password` | no | `onboarding.password` | Password for a newly created user, when it must differ from the authenticated account's new password. |
| `prompt_patterns` | no | built-ins | Named Python regex overrides for unusual appliances. |
| `debug` | no | `false` | Return sanitized per-attempt SSH sessions in `sessions`. |

Any non-username prompt ending in `name:` receives an empty response and do not affect the configured username. Pattern keys are `login_password`, `current_password`, `new_password`, `repeat_password`, `new_username`, `ignored_name`, `permission_denied`, `host_key_error`, and `success`.

## Result and safety

The result provides `credentials`, `attempts`, `changed`, and `onboarding_cancelled`. With `debug: true`, it also returns per-attempt `sessions`. Candidate and onboarding passwords are replaced with `********`; rejected passwords are never added deliberately.

- Pre-populate `known_hosts` where possible. Use `accept-new` only on controlled provisioning networks.
- Probing can trigger account lockout; keep candidate lists short and ordered.
- Vendor prompts vary; test regex overrides on an isolated target.
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
