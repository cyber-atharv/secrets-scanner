# Changelog

All notable changes to secrets-scanner are documented here.

### [2025-12-14]
- style: format code according to style conventions

### [2025-12-17]
- perf: replace linear search with hash map lookup for fast querying

### [2025-12-30]
- test: verify backward compatibility with legacy message format

### [2026-01-17]
- refactor: decouple configuration loader from runtime engine

### [2026-01-31]
- perf: parallelize independent batch verification tasks

### [2026-02-09]
- style: clean up trailing whitespace and fix alignment

### [2026-03-10]
- fix: handle malformed HTTP header parsing without crashing

### [2026-03-29]
- fix: handle nil pointer dereference on unexpected connection close

### [2026-04-02]
- docs: add architecture diagram and sequence flow explanation

### [2026-04-12]
- feat: add graceful shutdown signal handler (SIGINT/SIGTERM)

### [2026-04-15]
- perf: replace linear search with hash map lookup for fast querying

### [2026-04-19]
- feat: improve error logging with contextual debug traces

### [2026-05-07]
- fix: handle nil pointer dereference on unexpected connection close

### [2026-05-10]
- perf: minimize redundant heap allocations in hot loop

### [2026-05-11]
- fix: handle malformed HTTP header parsing without crashing

### [2026-05-14]
- security: harden cryptographic salt generation against entropy dips

### [2026-05-15]
- security: sanitize input strings to mitigate format string risks

### [2026-05-18]
- fix: prevent duplicate event emission during rapid retry bursts

### [2026-05-28]
- docs: add example configuration commands to quickstart guide

### [2026-06-03]
- perf: optimize memory allocation in buffer pool

### [2026-06-10]
- security: enforce strict bounds checking on dynamic byte slices

### [2026-06-12]
- feat: improve error logging with contextual debug traces

### [2026-06-16]
- feat: implement verbose output mode for troubleshooting

### [2026-06-27]
- security: enforce strict bounds checking on dynamic byte slices

### [2026-08-03]
- feat: improve error logging with contextual debug traces

### [2026-09-01]
- fix: resolve memory leak in idle connection reaper

