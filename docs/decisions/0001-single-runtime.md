# ADR 0001: Keep release lines isolated

## Status

Accepted.

## Decision

The supported PowerShell application and the unreleased Rust v3 workspace have
separate releases. Each maintains its own catalog, schemas, dispatcher, build,
test evidence, and release checks. Neither requires the other at runtime.
Tests of one implementation do not qualify the other's capabilities or releases.

## Rationale

PowerShell remains the supported application and the reference for behavior
comparisons. Rust v3 is a successor prototype with incomplete capabilities and
Windows verification. Separate releases let development continue without
presenting unfinished Rust code as a replacement for the PowerShell product.

Both implementations must meet the same security expectations: bounded input,
process execution without a shell, and a clear separation between requested
work and permission to change the system. They also require exact package
identity, short-lived elevation, authenticated local communication, approval
bound to a specific digest, and action records that reveal tampering. Each
implementation must demonstrate these properties through its own tests and
evidence.
