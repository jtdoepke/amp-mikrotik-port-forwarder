# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] - 2025-12-27

### Added

- AMP API client for fetching game server instances and extracting ports
- Mikrotik RouterOS API client for managing firewall rules
- Support for chains of N routers from WAN-facing to internal
- Automatic NAT rule creation for TCP and UDP port forwarding
- Hairpin NAT support for LAN clients accessing via external hostname
- Configuration via CLI flags with `--router` repeatable flag
- Configuration via environment variables with `AMP_SYNC_` prefix
- Indexed router configuration via environment variables (e.g., `AMP_SYNC_ROUTER_0_ADDRESS`)
- Password file support for Kubernetes-style mounted secrets
- Dry-run mode for testing changes without applying them
- Continuous polling mode with configurable interval
- One-shot sync mode for cron/timer-based execution
- Debug command for testing AMP API connectivity
- Version command showing build information
- Verbose logging mode
- TLS support for RouterOS API connections (port 8729)
- Systemd service files for continuous and timer-based operation
- Docker container image using distroless base
- GoReleaser configuration for multi-platform releases (linux/amd64, linux/arm64)
- GitHub Actions CI pipeline with linting, testing, and security scanning
- GitHub Actions release pipeline for automated releases
- Dependabot configuration for Go modules, GitHub Actions, and Docker
- Comprehensive test coverage for reconciliation logic
- Mock implementations for AMP and Mikrotik clients

[Unreleased]: https://github.com/jtdoepke/amp-mikrotik-port-forwarder/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/jtdoepke/amp-mikrotik-port-forwarder/releases/tag/v0.1.0
