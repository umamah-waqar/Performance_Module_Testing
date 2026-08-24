# Performance Module Test Bench

This repository serves as a target application to validate dynamic load testing, AST route discovery, p95 latency tracking, and bottleneck identification in the Nova testing platform.

## Endpoints Inventory

| Route | Method | Expected Latency | Expected Behavior |
| :--- | :--- | :--- | :--- |
| `/health` | GET | `< 15ms` | Baseline throughput |
| `/api/v1/users` | GET | `< 30ms` | Normal entity retrieval |
| `/api/v1/search` | GET | `~250ms` | Medium latency |
| `/api/v1/reports/heavy` | GET | `> 2000ms` | Triggers Critical Latency Bottleneck |
| `/api/v1/unstable` | GET | `~30ms` | Triggers 5xx Server Failure Bottleneck |
| `/api/v1/items` | POST | `< 20ms` | Requires payload / client validation |