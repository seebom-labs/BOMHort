# BOMHort Governance

This document describes the governance model for the BOMHort project.

## Principles

BOMHort is an open-source project licensed under [Apache 2.0](LICENSE). The project follows these principles:

- **Open** – All discussions, decisions, and code reviews happen in the open on GitHub.
- **Transparent** – Roadmap, architecture decisions, and meeting notes are publicly available.
- **Merit-based** – Contributions are judged on their technical quality and alignment with the project's goals, not on the contributor's affiliation.
- **Welcoming** – We strive to be an inclusive community where everyone feels safe and valued.

## Project Scope

BOMHort is a Kubernetes-native SBOM visualization and governance platform. The project's scope includes:

- Ingestion and parsing of SPDX SBOM files
- Vulnerability scanning via OSV and VEX assessment
- License compliance checking and policy enforcement
- Visualization and analytics of SBOM data at scale
- Helm-based deployment for Kubernetes clusters

Out of scope:

- SBOM generation (BOMHort consumes SBOMs, it does not create them)
- Container image scanning
- Runtime security monitoring

## Roles

### Users

Users are community members who use BOMHort. They contribute by filing bug reports, feature requests, and providing feedback. Anyone can be a user.

### Contributors

Contributors are community members who contribute to the project through code, documentation, tests, reviews, or other means. Anyone can become a contributor by submitting a pull request.

Contributors are expected to:

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Follow the coding standards documented in [AGENTS.md](AGENTS.md)
- Write tests for new features (see [docs/TESTING.md](docs/TESTING.md))
- Sign off their commits (Developer Certificate of Origin)

### Reviewers

Reviewers are contributors who have demonstrated sustained, high-quality contributions to a specific area of the codebase. They are granted the ability to approve pull requests in their area of expertise.

Reviewers are expected to:

- Provide timely, constructive reviews
- Ensure code quality, test coverage, and documentation
- Help mentor new contributors

Reviewers are nominated by maintainers and confirmed by lazy consensus (no objection within 7 days).

### Maintainers

Maintainers are the project's technical leadership. They are responsible for the overall direction, architecture, and health of the project. Maintainers have write access to the repository and the authority to merge pull requests.

Current maintainers:

| Name           | GitHub                                    | Area                | Affiliation |
|----------------|-------------------------------------------|---------------------|--------------|
| Mario Fahlandt | [@mfahlandt](https://github.com/mfahlandt) | Project Lead / Core | Kubermatic |
| Koray Oksay    | [@koksay](https://github.com/koksay)   | K8s Implementation  | Kubermatic |

Maintainers are responsible for:

- Setting the project's technical direction and roadmap
- Reviewing and merging pull requests
- Cutting releases
- Managing the CI/CD pipeline and infrastructure
- Resolving disputes between contributors
- Enforcing the Code of Conduct

New maintainers are nominated by existing maintainers and approved by a supermajority (two-thirds) of current maintainers.

### Emeritus

Maintainers or reviewers who are no longer active may be moved to emeritus status. Emeritus members are recognized for their past contributions but no longer have active review or merge permissions. They can return to active status by request and re-confirmation from existing maintainers.

## Decision Making

### Lazy Consensus

Most decisions are made through lazy consensus. A proposal is considered accepted if:

1. The proposal is made via a GitHub issue or pull request
2. A reasonable amount of time has passed (at least 72 hours for non-trivial changes)
3. No maintainer has raised an objection

### Voting

For contentious decisions where lazy consensus cannot be reached, a vote is called:

- Each maintainer has one vote
- A simple majority (>50%) is required for most decisions
- A supermajority (≥ two-thirds) is required for:
  - Changes to this governance document
  - Adding or removing maintainers
  - Changes to the project's license
  - Changes to the project's scope

### Architecture Decisions

Significant architectural decisions are documented in the [Architecture Plan](docs/ARCHITECTURE_PLAN.md) and its decision log. These decisions follow the lazy consensus process but require at least one maintainer approval and a 7-day review period.

## Contributions

### Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes following the project's coding standards
3. Write or update tests as needed (see [docs/TESTING.md](docs/TESTING.md))
4. Submit a pull request with a clear description
5. Address review feedback
6. A maintainer will merge the PR once approved

### Requirements for Merge

- All CI checks pass (Go tests, Angular build, Helm lint)
- At least one maintainer approval
- No unresolved objections
- Tests cover new functionality
- Documentation updated if user-facing behavior changes

## Releases

Releases follow [Semantic Versioning](https://semver.org/):

- **Patch** (0.1.x) – Bug fixes, no API changes
- **Minor** (0.x.0) – New features, backward-compatible
- **Major** (x.0.0) – Breaking changes

Release process is documented in [docs/RELEASE.md](docs/RELEASE.md). Any maintainer can cut a release by tagging a commit on `main`.

## Code of Conduct

All community members are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Violations should be reported to the maintainers. Maintainers will review and address reports confidentially.

## Changes to Governance

Changes to this document require a pull request and approval by a supermajority (two-thirds) of current maintainers, with a minimum review period of 14 days.

---
