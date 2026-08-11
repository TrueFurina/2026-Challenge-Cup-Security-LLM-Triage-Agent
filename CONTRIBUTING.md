# Contributing

## Scope

This repository is a starter project for an AI security agent demo. Contributions should keep the project simple, inspectable, and easy to run in restricted environments.

## Development Guidelines

- Prefer standard-library solutions unless a dependency is clearly justified.
- Keep the CLI and Web UI aligned with the same backend orchestration flow.
- Preserve mock mode so the demo remains runnable without external services.
- Add concise comments only where the code would otherwise be hard to read.

## Suggested Workflow

1. Create a focused branch.
2. Make the smallest coherent change that solves one problem.
3. Run the smoke-test commands from `README.md`.
4. Update docs if behavior or configuration changed.

## Pull Request Notes

Include:

- what changed
- why it changed
- how it was tested
- any follow-up work intentionally left out
