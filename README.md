# CoroditeP2P

CoroditeP2P is an open, deterministic, offline-first peer infrastructure for environments where connectivity is weak, unstable, intermittent, or intentionally limited.

Instead of assuming permanent cloud access, central coordination, or continuous background synchronization, CoroditeP2P starts from the opposite assumption:

- nodes may disappear and return
- connectivity may only exist partially
- interruption is normal
- local state remains primary
- synchronization must be controlled instead of blindly assumed

CoroditeP2P is not just another sync layer. It is a state-oriented peer infrastructure designed around explicit state, deterministic transitions, controlled re-entry, replay-aware communication, and low-overhead operation on small or heterogeneous hardware.

## Goals

The project aims to provide an open and reusable infrastructure component for systems that need:

- offline-first behavior
- local-first operation
- explicit peer state handling
- controlled reconnection and resynchronization
- reproducible system behavior
- stronger data sovereignty
- less dependence on centralized infrastructure

## Core ideas

CoroditeP2P is based on a few simple principles:

- **local truth remains primary**
- **connectivity is negotiated instead of assumed**
- **synchronization happens as a controlled event**
- **interruption, return, and partial connectivity are normal conditions**
- **deterministic state transitions are preferred over vague recovery logic**
- **low-overhead operation matters**

## Why this project exists

Many modern systems are built around permanent connectivity, central services, and hidden background synchronization. In real environments, those assumptions often fail.

CoroditeP2P is intended for use cases where systems must remain coherent even when the network does not.

This includes, for example:

- mobile and distributed work systems
- edge and local infrastructure
- privacy-sensitive deployments
- weak-connectivity environments
- resilient peer-based systems
- independent and sovereignty-oriented digital systems

## Current status

This repository is the public project base for CoroditeP2P.

The project is currently in an early public stage. Some earlier internal notes and documentation are being reconstructed and prepared for open publication.

The repository will be expanded step by step with:

- protocol notes
- state and transition semantics
- implementation work
- test tooling
- field-study preparation
- technical documentation

## Planned outputs

The intended public outputs of this project are:

- an open protocol specification
- a reference implementation
- explicit state and transition semantics
- reproducible multi-node test setups
- public technical documentation
- field evaluation notes

## License

This project is licensed under the Apache License 2.0.

## Development philosophy

CoroditeP2P is developed as open infrastructure, not as a lock-in platform.

The intention is to build something that others can:

- use
- study
- modify
- extend
- and integrate into independent systems

## Repository structure

```
docs/    — protocol notes, architecture, state model, field-testing notes
spec/    — protocol and transition semantics
src/     — reference implementation
tests/   — reproducible test setups and validation logic
tools/   — instrumentation and helper tooling
```

## Contribution status

External contributions may be accepted later. During the current early phase, the main focus is on stabilizing the public structure, rebuilding documentation, and establishing the first implementation baseline.

## Contact / project note

No public website exists yet. This repository currently serves as the public starting point for the project.
