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
