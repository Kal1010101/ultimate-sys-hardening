# Contributing to Ultimate Hardening

We love your input! We want to make contributing to this project as easy and transparent as possible.

This project is actively maintained. Expect a reply to issues and pull requests in a timely manner.

## Development Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure your code passes ShellCheck.
5. Issue that pull request!

## Pull Request Process

1. Update the README.md with details of changes if needed.
2. Update the docs/ with any new configuration parameters.
3. The PR will be merged once you have the sign-off of at least one maintainer.

### What CI checks on a pull request

This tool runs as root, so every PR gets a careful read, and CI points the
reviewer at the parts that need it. The **PR risk check** marks changes to CI,
packaging, install and update code, binary files, symlinks, new executables,
long encoded strings, new download or network calls, and `eval`/`exec`. These
are warnings, not accusations: plenty of good PRs touch them, and they simply
get a closer look. Hidden or bidirectional Unicode characters fail the check;
replace them with plain text. Workflow changes are also audited by
[zizmor](https://docs.zizmor.sh). ShellCheck, CodeQL, gitleaks and the
multi-distro tests run as well. A first-time contributor's CI starts once a
maintainer approves it.

## Reporting Issues

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/Kal1010101/ultimate-sys-hardening/issues/new/choose).

## Licensing

- **Free tier contributions**: MIT License
- **Pro/Enterprise contributions**: Must sign a Contributor License Agreement (CLA)

## Code of Conduct

### Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone.

### Our Standards

Examples of behavior that contributes to a positive environment:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project team at ultimate-sys-hardening@protonmail.com.
