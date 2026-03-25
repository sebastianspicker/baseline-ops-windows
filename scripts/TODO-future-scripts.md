# TODO: Future Audit Scripts

The following security audit areas are not yet covered by dedicated scripts:

- **AMSI (Antimalware Scan Interface) Audit**: Verify AMSI providers are registered and
  functioning, detect AMSI bypass attempts, and validate AMSI integration with PowerShell
  and other scripting hosts.

- **AppLocker Audit**: Enumerate AppLocker policies, verify enforcement mode per rule
  collection (Exe, Script, MSI, DLL, Packaged), detect gaps in coverage, and report
  on audit-only vs. enforced rules.

- **DNS-over-HTTPS (DoH) Audit**: Check Windows DNS client DoH configuration, verify
  DoH server endpoints, audit whether plaintext DNS fallback is permitted, and validate
  alignment with organizational DNS security policy.
