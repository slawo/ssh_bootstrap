# Contributing

Use focused changes and Conventional Commit messages such as `feat:`, `fix:`,
`docs:`, `test:`, and `ci:`. Breaking changes use `!` or a `BREAKING CHANGE:`
footer.

Before opening a pull request, run:

```shell
python3 -m unittest discover -s tests/unit -v
ansible-lint .
ansible-galaxy collection build --output-path dist --force
```

Never commit credentials or unsanitized SSH session output. Candidate and new
passwords belong in Ansible Vault or an external secret manager.

## Development container

Open this repository in its devcontainer for an isolated Docker daemon, GitHub
CLI, Ansible tooling, SSH/network diagnostics, and the linters used by CI.
Authenticate GitHub CLI after creation with `gh auth login`; credentials are
not baked into the image or repository.

Temporary diagnostics and handoff notes belong under `work/`, which is ignored
to prevent VM logs, session captures, and credentials from being committed.

The OpenBSD VM job caches the immutable post-`prepare` image. Set the repository
variable `DEBUG_ON_ERROR=true` to make vmactions pause a failed VM and expose its
interactive VNC debugging link. Leave it unset for normal unattended CI.

The `Development container` CI job builds the complete configuration, including
features, and runs its toolchain smoke test. A local rebuild should produce the
same result from VS Code's **Dev Containers: Rebuild Container Without Cache**
command if a cached APT layer is unhealthy.
