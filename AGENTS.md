# Contributor instructions

This repository contains the `slawo.ssh_bootstrap` Ansible collection.

- Keep controller-side SSH behavior deterministic, bounded, and password-safe.
- Never add real credentials, SSH keys, known-host data, or session captures.
- Preserve strict host-key checking as the default.
- Store controller-only shared implementation in private `plugins/plugin_utils/_*.py` files.
- Add unit tests for prompt-state changes and integration tests for SSH behavior.
- Use FQCNs in examples and documentation.
- Run `python3 -m unittest discover -s tests/unit`, `ansible-lint .`, and
  `ansible-galaxy collection build --output-path dist --force` before release.
- Use Conventional Commit prefixes so Release Please can calculate versions.
