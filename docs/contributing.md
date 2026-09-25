# Contributing

The [repository contributor guide](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md)
is the canonical source for development setup, quality gates, review policy,
commit sign-off and the pull request process. Keeping these requirements in one
place avoids conflicting instructions between the website and the repository.

## First contribution

1. Read the [community guide](community.md) and
   [security policy](security.md).
2. Search [open issues](https://github.com/aisecnomad/Project-Nexus/issues) for
   related work. Documentation fixes and small synthetic reproductions are
   useful contributions.
3. For significant changes, open an issue first to agree on scope and the
   approach. Follow the contributor guide to create a local development
   environment and submit a focused pull request.

## Try one test

The contributor guide's
[Run one test section](https://github.com/aisecnomad/Project-Nexus/blob/main/CONTRIBUTING.md#run-one-test)
provides a credential-free first test, the existing Make targets, and the exact
coverage-report command. Follow it after setting up your development environment.

## Technical guides

- [Architecture and connector contract](architecture.md)
- [Connector configuration and permissions](connectors.md)
- [Signature authoring](signatures.md)
- [Detection evaluation](evaluation.md)
- [Deployment and acceptance evidence](production.md)
- [Architectural decisions](adrs/index.md)

Use synthetic fixtures and authorized inputs. Never put live credentials,
private exports or confidential source code in a public issue or pull request.
