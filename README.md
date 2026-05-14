# AUTOSAR Intrusion Detection System Manager (IDSM) Toolkit

A production-pattern, async-first C++17/C11 implementation of the AUTOSAR Intrusion Detection System Manager per specifications R20-11 & R22-11. Provides a thread-safe, non-blocking manager layer for orchestrating multiple IDS detectors, event buffering, flood protection, and seamless BSW integration.

## Features

- **Async/Non-Blocking Core**: Background worker thread processes events instantly without blocking detector/communication threads
- **AUTOSAR-Compliant C API**: `IdsM_Init`, `IdsM_ReportEvent`, `IdsM_SetOperatingMode`, `IdsM_MainFunction` (simulated)
- **IDSRM SOC Forwarding**: HTTP POST violations to any Security Operations Center endpoint (Splunk, QRadar, Elastic, custom webhook)
- **Dynamic Payload**: Variable-length payload buffer (deep-copied) — supports CAN 2.0 (13B), CAN FD (69B), Ethernet (1514B), or any custom context
- **Pluggable Module Architecture**: Lightweight Adapter pattern for integrating CAN IDS, SecOC, FlexRay, Ethernet, or custom detectors
- **Thread-Safe State Management**: Mutex-protected queues, condition variables, and atomic flags
- **Event Buffering & Flood Protection**: Configurable per-monitor acceptance windows and anti-spam filtering
- **Lifecycle Mode Management**: Pre-Run, Run, and Post-Run operating modes with selective monitor activation
- **Comprehensive Test Suite**: 39 tests (Google Test) covering IDSM unit, IDSRM unit, and HTTP integration
- **Interactive CLI**: Real-time testing, status querying, IDSRM control, and diagnostic flushing

---

## Architecture Overview

The toolkit follows a **Manager-Adapter-Detector** pattern aligned with AUTOSAR BSW layering, with an optional **IDSRM reporting** layer:

```
[Detector Engine] → [Adapter] → IdsM_ReportEvent()
                                        ↓
                                [IDSM Manager (Async Worker)]
                                        ↓
                                IdsM_DemReportCallback
                                        ↓
                          [IDSRM Worker Thread] → HTTP POST → SOC Endpoint
```

- **Detector Engine**: Validates frames/signals (e.g., CAN IDS, SecOC verifier)
- **Adapter**: Translates detector violations into `IdsM_EventReportType` and forwards to IDSM
- **IDSM Manager**: Thread-safe queue + background worker handles buffering, flood protection, and DEM forwarding
- **IDSRM Module**: Optional. Registers as the DEM callback, enqueues events to its own worker thread, and HTTP POSTs JSON to a configurable SOC URL via libcurl

---

## Project Structure

```
autosar-idsm-toolkit/
├── include/
│   ├── IdsM_Types.h               # AUTOSAR type definitions, enums, config structs
│   ├── IdsM.h                     # Public C API for IDSM
│   ├── IdsM_Internal.h            # C++ IdsM_Manager singleton, IdsM_OwnedEvent (deep-copy)
│   ├── IdsM_Manager_Wrapper.h     # C/C++ bridge for IDSM
│   ├── IdsRm_Types.h              # IDSRM config, stats, return codes
│   ├── IdsRm.h                    # Public C API for IDSRM
│   ├── IdsRm_Internal.h           # C++ IdsRm_Manager singleton class
│   └── IdsRm_Manager_Wrapper.h    # C/C++ bridge for IDSRM
├── src/
│   ├── IdsM.c                     # IDSM C wrapper
│   ├── IdsM_Manager.cpp           # IDSM async worker implementation
│   ├── IdsRm.c                    # IDSRM C wrapper
│   └── IdsRm_Manager.cpp          # IDSRM async HTTP forwarding (libcurl)
├── apps/
│   └── idsm_cli/
│       └── main.cpp               # Interactive CLI with IDSRM commands
├── tests/
│   ├── test_idsm.cpp              # 20 IDSM unit tests (Google Test)
│   ├── test_idsrm.cpp             # 19 IDSRM unit + integration tests
│   └── mock_soc_server.py         # Python mock SOC endpoint for manual testing
└── CMakeLists.txt
```

---

## IDSM Configuration Reference

### `IdsM_MonitorConfigType` — per-monitor, set at `IdsM_Init()`

| Field | Type | Description |
|:---|:---|:---|
| `monitor_id` | `uint16_t` | Unique identifier for this detector |
| `event_buffer_size` | `uint32_t` | Ring buffer capacity; oldest event dropped on overflow |
| `flood_protection_ms` | `uint32_t` | Minimum milliseconds between DEM forwards (0 = disabled) |
| `severity_threshold` | `IdsM_EventSeverityType` | Minimum severity to accept (LOW / MEDIUM / HIGH / CRITICAL) |
| `enabled_in_pre_run` | `boolean` | Active during PRE_RUN_MODE |
| `enabled_in_run` | `boolean` | Active during RUN_MODE |
| `enabled_in_post_run` | `boolean` | Active during POST_RUN_MODE |

**Example:**
```c
IdsM_MonitorConfigType configs[2] = {
    // {MonitorID, BufferSize, FloodWindow_ms, Severity,    PreRun, Run, PostRun}
    {0x001, 20, 100, IDSM_SEVERITY_HIGH,       true,  true,  false}, // CAN IDS
    {0x002, 10,  50, IDSM_SEVERITY_CRITICAL,    true,  true,  true}  // SecOC
};
IdsM_Init(configs, 2);
IdsM_SetOperatingMode(IDSM_RUN_MODE);
```

### `IdsM_EventReportType` — event submitted via `IdsM_ReportEvent()`

| Field | Type | Description |
|:---|:---|:---|
| `monitor_id` | `uint16_t` | Which monitor detected the violation |
| `event_id` | `uint16_t` | Unique event identifier within this monitor |
| `timestamp_ms` | `uint32_t` | Event timestamp in milliseconds |
| `payload` | `const uint8_t*` | Caller-owned buffer with context data (deep-copied on enqueue) |
| `payload_len` | `uint16_t` | Byte count of payload (any size: CAN=13B, CAN-FD=69B, Ethernet=1514B) |
| `severity` | `IdsM_EventSeverityType` | LOW / MEDIUM / HIGH / CRITICAL |

> **Note:** `payload` is a pointer to a caller-owned buffer. IDSM deep-copies the bytes
> into an internal `std::vector<uint8_t>` when `IdsM_ReportEvent()` is called, so the
> caller's buffer can safely go out of scope immediately after the call returns.

### IDSM Public API

| Function | Description |
|:---|:---|
| `IdsM_Init(config, count)` | Initialize manager, start async worker |
| `IdsM_DeInit()` | Stop worker, join thread, clear state |
| `IdsM_SetOperatingMode(mode)` | Switch PRE_RUN / RUN / POST_RUN |
| `IdsM_GetOperatingMode()` | Query current mode |
| `IdsM_ReportEvent(event)` | Submit event to async queue (non-blocking, <1us) |
| `IdsM_GetDetectionStatus(id)` | Get monitor violation status |
| `IdsM_ResetDetectionStatus(id)` | Clear violation flag |
| `IdsM_GetPendingEventCount(id)` | Count buffered events |
| `IdsM_FlushEvents(id)` | Force-forward all buffered events |
| `IdsM_SetDemReportCallback(cb)` | Register DEM callback (IDSRM sets this automatically) |
| `IdsM_SetNvmStoreCallback(cb)` | Register NVM callback |

---

## IDSRM Module — SOC Violation Forwarding

The IDSRM (Intrusion Detection System Reporting Module) forwards IDSM violations to a Security Operations Center via HTTP POST. **You do not need to build a SOC portal** — IDSRM sends JSON to any HTTP endpoint you point it at (Splunk HEC, QRadar, Elastic webhook, custom server, etc.).

### How It Works

1. `IdsRm_Init()` registers itself as the IDSM DEM callback
2. When the IDSM worker fires the callback, IDSRM enqueues the event (<1us, non-blocking)
3. IDSRM's own worker thread picks up events and HTTP POSTs JSON to the SOC URL
4. Failed requests retry with exponential backoff (100ms, 200ms, 400ms...)

### `IdsRm_ConfigType` — set at `IdsRm_Init()`, URL/token changeable at runtime

| Field | Type | Description |
|:---|:---|:---|
| `soc_url` | `char[256]` | HTTP/HTTPS endpoint (e.g. `https://soc.company.com/api/violations`) |
| `auth_token` | `char[512]` | Bearer token for `Authorization` header; empty string = no header |
| `timeout_ms` | `uint32_t` | Per-request HTTP timeout in milliseconds |
| `retry_count` | `uint8_t` | Number of retries on failure (max 10, exponential backoff) |
| `enabled` | `boolean` | Initial enabled/disabled state |

### Compile-Time Constants

| Constant | Default | Description |
|:---|:---|:---|
| `IDSRM_MAX_URL_LEN` | 256 | Maximum SOC URL length |
| `IDSRM_MAX_TOKEN_LEN` | 512 | Maximum auth token length |
| `IDSRM_MAX_RETRY_COUNT` | 10 | Hard cap on retry_count |
| `IDSRM_DEFAULT_QUEUE_DEPTH` | 128 | Max queued events before dropping |

### IDSRM Public API

| Function | Description |
|:---|:---|
| `IdsRm_Init(config)` | Initialize IDSRM, register DEM callback, start worker. Call after `IdsM_Init()`. |
| `IdsRm_DeInit()` | Drain remaining events, stop worker, unregister callback |
| `IdsRm_Enable()` | Enable forwarding (no-op if already enabled) |
| `IdsRm_Disable()` | Disable forwarding; events silently dropped. Worker keeps running. |
| `IdsRm_IsEnabled()` | Returns `true` if initialized AND enabled |
| `IdsRm_SetSocUrl(url)` | Update SOC URL at runtime (thread-safe, takes effect on next POST) |
| `IdsRm_SetAuthToken(token)` | Update bearer token at runtime (pass `""` to remove) |
| `IdsRm_GetStats()` | Get snapshot: received, dropped, posted, failed, retries |
| `IdsRm_ResetStats()` | Reset all counters to zero |

### JSON Payload Format

Each violation is POSTed as:
```json
{
    "monitor_id": 1,
    "event_id": 256,
    "timestamp_ms": 42000,
    "severity": "HIGH",
    "payload": "00000123080102030405060708",
    "payload_len": 13
}
```

The `payload` field is a hex-encoded byte string (e.g., CAN frame: 4B CAN-ID + 1B DLC + 8B data = 13 bytes → `"00000123080102030405060708"`). `payload_len` is the original byte count.

### Usage Example

```c
#include "IdsM.h"
#include "IdsRm.h"

/* 1. Initialize IDSM */
IdsM_MonitorConfigType mon = {0x001, 20, 100, IDSM_SEVERITY_HIGH, true, true, false};
IdsM_Init(&mon, 1);
IdsM_SetOperatingMode(IDSM_RUN_MODE);

/* 2. Initialize IDSRM — must be called after IdsM_Init() */
IdsRm_ConfigType rm_cfg = {};
strncpy(rm_cfg.soc_url, "https://soc.company.com/api/idsm-violations", IDSRM_MAX_URL_LEN - 1);
strncpy(rm_cfg.auth_token, "my-bearer-token", IDSRM_MAX_TOKEN_LEN - 1);
rm_cfg.timeout_ms  = 3000;
rm_cfg.retry_count = 2;
rm_cfg.enabled     = true;
IdsRm_Init(&rm_cfg);

/* 3. Report violations as normal — IDSRM forwards them to the SOC automatically */
uint8_t context[] = {0x00, 0x00, 0x01, 0x23, 0x08,       /* CAN ID + DLC */
                     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; /* CAN data */
IdsM_EventReportType evt = {0x001, 0x100, 42000, context, sizeof(context), IDSM_SEVERITY_HIGH};
IdsM_ReportEvent(&evt);  /* deep-copies payload internally */

/* 4. Check stats */
IdsRm_StatsType stats = IdsRm_GetStats();
printf("posted=%u failed=%u\n", stats.events_posted, stats.events_failed);

/* 5. Runtime control */
IdsRm_Disable();                    /* pause forwarding */
IdsRm_Enable();                     /* resume */
IdsRm_SetSocUrl("http://backup-soc:8080/api/violations"); /* switch endpoint */

/* 6. Shutdown (IDSRM first, then IDSM) */
IdsRm_DeInit();
IdsM_DeInit();
```

---

## Async Behavior & Threading Model

- `IdsM_ReportEvent()` is non-blocking: deep-copies payload into `std::vector<uint8_t>`, pushes to queue, and returns in <1us
- **Deep-Copy Ownership**: Payload bytes are copied at every queue boundary (IDSM enqueue, IDSRM enqueue). The caller's buffer can go out of scope immediately after `IdsM_ReportEvent()` returns.
- **IDSM Worker Thread**: Wakes on event submission, processes flood protection, buffers events, forwards to DEM callback
- **IDSRM Worker Thread**: Separate thread. Receives events from DEM callback, HTTP POSTs via libcurl. Uses TCP keep-alive for connection reuse.
- **Thread Safety**: All public APIs are mutex-protected. Safe to call from CAN RX threads, SecOC verifiers, or OS tasks
- **Flood Protection**: Configurable `flood_protection_ms` per monitor drops rapid duplicate violations
- **Mode Isolation**: Events submitted in disabled modes are rejected instantly with `E_MODE_INVALID`

---

## How to Integrate External Modules (e.g., CAN IDS Toolkit)

**Step 1:** Create an Adapter Class

```cpp
#pragma once
#include "IdsM.h"
#include <cstring>
#include <vector>

class CanIdsToIdsMAdapter {
public:
    explicit CanIdsToIdsMAdapter(IdsM_MonitorIdType monitor_id) : m_monitor_id(monitor_id) {}

    void reportViolation(uint16_t event_id, IdsM_EventSeverityType severity,
                         const CanFrame& frame) {
        /* Pack CAN context: [CAN_ID (4B)] [DLC (1B)] [DATA (up to 8B)] = 13B for CAN 2.0 */
        std::vector<uint8_t> buf(4 + 1 + frame.dlc);
        uint32_t can_id = frame.id;
        std::memcpy(&buf[0], &can_id, sizeof(can_id));
        buf[4] = frame.dlc;
        std::memcpy(&buf[5], frame.data, frame.dlc);

        IdsM_EventReportType evt{};
        evt.monitor_id   = m_monitor_id;
        evt.event_id     = event_id;
        evt.severity     = severity;
        evt.timestamp_ms = get_platform_timestamp_ms();
        evt.payload      = buf.data();   // IDSM deep-copies on enqueue
        evt.payload_len  = static_cast<uint16_t>(buf.size());

        IdsM_ReportEvent(&evt);  // non-blocking, deep-copies payload
    }

private:
    IdsM_MonitorIdType m_monitor_id;
};
```

The `payload` field is a **dynamic pointer** — IDSM deep-copies the bytes internally.
Any size is supported: CAN 2.0 (13B), CAN FD (69B), Ethernet (1514B), etc.

**Step 2:** Register Monitor in IDSM Configuration

```cpp
IdsM_MonitorConfigType configs[2] = {
    {0x001, 20, 100, IDSM_SEVERITY_HIGH,     true, true, false}, // CAN IDS
    {0x002, 10,  50, IDSM_SEVERITY_CRITICAL,  true, true, true}  // SecOC
};
IdsM_Init(configs, 2);
IdsM_SetOperatingMode(IDSM_RUN_MODE);

CanIdsToIdsMAdapter can_ids_adapter(0x001);
```

**Step 3:** Link in CMakeLists.txt

```cmake
add_subdirectory(modules/can-ids-toolkit)
target_link_libraries(your_app PRIVATE idsm_core idsrm_core can_ids_core)
```

**Step 4:** Forward Violations in RX Callback

```cpp
void onCanFrameReceived(const CanFrame& frame) {
    auto result = can_ids_engine.validateFrame(frame);
    if (result.status != CanIdsResult::Status::Valid) {
        can_ids_adapter.reportViolation(0x10, IDSM_SEVERITY_HIGH, frame);
    }
}
```

---

## Build & Run

### Prerequisites

| Component | Requirement | Arch Linux | Ubuntu/Debian |
|:---|:---|:---|:---|
| **Compiler** | GCC 11+ / Clang 14+ | `sudo pacman -S base-devel` | `sudo apt install build-essential` |
| **Build System** | CMake 3.16+ | `sudo pacman -S cmake` | `sudo apt install cmake` |
| **libcurl** | Required for IDSRM | `sudo pacman -S curl` | `sudo apt install libcurl4-openssl-dev` |
| **Python 3** | Optional (mock SOC server) | pre-installed | pre-installed |

### Compile

```bash
git clone https://github.com/niketdhale/autosar-idsm-toolkit.git
cd autosar-idsm-toolkit
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

### Run CLI

```bash
./build/idsm_cli
```

### CLI Usage

```bash
# Initialize IDSM + IDSRM (auto-connects to localhost:8080)
init

# Switch to normal driving mode
mode run

# Simulate a detector violation (processed async, forwarded to SOC)
# pay= takes a hex byte string: e.g., CAN ID 0x123 + DLC 8 + 8 data bytes
report mon=0x001 evt=0x100 sev=2 pay=000001230801020304050607FF

# Query IDSM monitor status
status 0x001

# Force flush buffered events
flush 0x001

# IDSRM controls
idsrm status                          # show enabled state + stats
idsrm disable                         # pause SOC forwarding
idsrm enable                          # resume SOC forwarding
idsrm url http://new-soc:9090/api/v2  # change SOC endpoint at runtime
idsrm token my-new-bearer-token       # update auth token

# Graceful shutdown
quit
```

### Manual Testing with Mock SOC Server

```bash
# Terminal 1: Start the mock SOC server
python3 tests/mock_soc_server.py 8080

# Terminal 2: Run the CLI
./build/idsm_cli
init
mode run
report mon=0x001 evt=0x100 sev=2 pay=000001230801020304050607FF
idsrm status   # events_posted should be 1
quit
```

The mock server validates JSON structure and prints received events.

---

## Testing

The project uses Google Test (fetched automatically via CMake FetchContent).

### Run All Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
cd build && ctest --output-on-failure
```

### Test Coverage

| Suite | Tests | Description |
|:---|:---:|:---|
| **IdsMTest** | 20 | Lifecycle, mode management, event reporting, DEM callback, flood protection, detection status, multi-monitor |
| **IdsRmPreInitTest** | 5 | Guard clauses: all APIs return error before `IdsRm_Init()` |
| **IdsRmTest** | 8 | Init/DeInit, enable/disable toggle, stats tracking, null-pointer guards |
| **IdsRmIntegrationTest** | 6 | In-process mock HTTP server: event posting, JSON validation, disable/enable, runtime URL change, multi-event |
| **Total** | **39** | All tests pass |

The IDSRM integration tests use an in-process POSIX socket server — no external Python server needed for automated testing.

---

## AUTOSAR Compliance Notes

| Specification Requirement | Status | Notes |
|:---|:---:|:---|
| **Initialization/DeInit** | Compliant | [SWS_IdM_00100-00101] |
| **Main Function (Runnable)** | Compliant | [SWS_IdM_00102] (async worker) |
| **Operating Mode Management** | Compliant | [SWS_IdM_00103-00104] |
| **Event Reporting Interface** | Compliant | [SWS_IdM_00200] (thread-safe) |
| **Detection Status Query** | Compliant | [SWS_IdM_00201-00202] |
| **DEM Event Forwarding** | Simulated | [SWS_IdM_00300] (callback-based) |
| **NVM Config Persistence** | Simulated | [SWS_IdM_00301] (in-memory only) |
| **Multi-Monitor Orchestration** | Compliant | [SWS_IdM_00400] |
| **Flood/Acceptance Windows** | Compliant | [SWS_IdM_00500] |

> **Simulator Disclaimer:** This toolkit is designed for HIL testing, simulation, and educational purposes. Production vehicle deployment requires integration with AUTOSAR OS tasks, COM/PduR routing, DEM/NVM/Csm modules, secure key storage, and ISO 21434 cybersecurity validation.

MIT License. See LICENSE for details.
