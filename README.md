# AUTOSAR Intrusion Detection System Manager (IDSM) Toolkit

A production-pattern, async-first C++17/C11 implementation of the AUTOSAR Intrusion Detection System Manager per specifications R20-11 & R22-11. Provides a thread-safe, non-blocking manager layer for orchestrating multiple IDS detectors, event buffering, flood protection, and seamless BSW integration.

## Features
- **Async/Non-Blocking Core**: Background worker thread processes events instantly without blocking detector/communication threads
- **AUTOSAR-Compliant C API**: `IdsM_Init`, `IdsM_ReportEvent`, `IdsM_SetOperatingMode`, `IdsM_MainFunction` (simulated)
- **Pluggable Module Architecture**: Lightweight Adapter pattern for integrating CAN IDS, SecOC, FlexRay, Ethernet, or custom detectors
- **Thread-Safe State Management**: Mutex-protected queues, condition variables, and atomic flags
- **Event Buffering & Flood Protection**: Configurable per-monitor acceptance windows and anti-spam filtering
- **Lifecycle Mode Management**: Pre-Run, Run, and Post-Run operating modes with selective monitor activation
- **Zero External Dependencies**: Pure C11/C++17 + STL (no Qt, no Boost, no OpenSSL required)
- **Interactive CLI**: Real-time testing, status querying, and diagnostic flushing

---

## Architecture Overview

The IDSM follows a **Manager-Adapter-Detector** pattern aligned with AUTOSAR BSW layering:

[Physical/Logical Bus] → [Detector Engine] → [Adapter] → IdsM_ReportEvent() → [IDSM Manager (Async)] → [DEM Callback]
CAN/FlexRay/Eth (CAN IDS) (C++ Class) (Non-Blocking) (Background Thread) (Diagnostics)


- **Detector Engine**: Validates frames/signals (e.g., `can-ids-toolkit`, SecOC verifier)
- **Adapter**: Translates detector violations into `IdsM_EventReportType` and forwards to IDSM
- **IDSM Manager**: Thread-safe queue + background worker handles buffering, flood protection, and DEM forwarding
- **DEM Callback**: Simulates AUTOSAR Diagnostic Event Manager integration

---
## Async Behavior & Threading Model

- IdsM_ReportEvent() is non-blocking: Pushes event to a lock-free-ish queue and returns in <1µs
- Background Worker Thread: Wakes on event submission, processes flood protection, buffers events, and forwards to DEM
- Thread Safety: All public APIs are mutex-protected. Safe to call from CAN RX threads, SecOC verifiers, or OS tasks
- Flood Protection: Configurable flood_protection_ms per monitor drops rapid duplicate violations automatically
- Mode Isolation: Events submitted in disabled modes (e.g., Pre-Run) are rejected instantly with E_MODE_INVALID
---
## How to Integrate External Modules (e.g., CAN IDS Toolkit)

Step 1: Create an Adapter Class
Wrap your detector in a thread-safe adapter that forwards violations to the IDSM:

```cpp
// src/adapters/CanIdsToIdsMAdapter.hpp
#pragma once
#include "IdsM.h"
#include "../modules/can-ids-toolkit/include/CanIdsEngine.h"

class CanIdsToIdsMAdapter {
public:
    explicit CanIdsToIdsMAdapter(IdsM_MonitorIdType monitor_id) : m_monitor_id(monitor_id) {}

    // Call from your CAN RX thread when a violation is detected
    void reportViolation(uint16_t event_id, IdsM_EventSeverityType severity, uint32_t context_payload) {
        IdsM_EventReportType evt{};
        evt.monitor_id   = m_monitor_id;
        evt.event_id     = event_id;
        evt.severity     = severity;
        evt.payload      = context_payload;
        evt.timestamp_ms = get_platform_timestamp_ms(); // Implement per OS/RTOS

        // Thread-safe, non-blocking submission to async IDSM
        IdsM_ReportEvent(&evt);
    }

private:
    IdsM_MonitorIdType m_monitor_id;
};
```
Step 2: Register Monitor in IDSM Configuration, Configure the IDSM to recognize your detector's monitor ID:
```cpp
IdsM_MonitorConfigType configs[2] = {
    // {MonitorID, BufferSize, FloodWindow_ms, Severity, PreRun, Run, PostRun}
    {0x001, 20, 100, IDSM_SEVERITY_HIGH,   true,  true,  false}, // CAN IDS
    {0x002, 10, 50,  IDSM_SEVERITY_CRITICAL, true,  true,  true}  // SecOC Verifier
};

IdsM_Init(configs, 2);
IdsM_SetOperatingMode(IDSM_RUN_MODE);

CanIdsToIdsMAdapter can_ids_adapter(0x001);
```
Step 3: Link in CMakeLists.txt, Add your detector as a subdirectory and link it to your application:
```cpp
# Add detector module
add_subdirectory(modules/can-ids-toolkit)

# Link to your app or IDSM core
target_link_libraries(your_app PRIVATE idsm_core can_ids_core)
target_sources(your_app PRIVATE src/adapters/CanIdsToIdsMAdapter.cpp)
```
Step 4: Forward Violations in RX Callback
```cpp
void onCanFrameReceived(const CanFrame& frame) {
    auto result = can_ids_engine.validateFrame(frame);
    if (result.status != CanIdsResult::Status::Valid) {
        // Returns instantly. Background thread handles processing & DEM forwarding.
        can_ids_adapter.reportViolation(0x10, IDSM_SEVERITY_HIGH, frame.id);
    }
}
```
## Build & Run
### Prerequisites

| Component | Requirement | Arch Linux | Ubuntu/Debian |
| :--- | :--- | :--- | :--- |
| **Compiler** | GCC 11+ / Clang 14+ | `sudo pacman -S base-devel` | `sudo apt install build-essential` |
| **Build System** | CMake 3.16+, Ninja | `sudo pacman -S cmake ninja` | `sudo apt install cmake ninja-build` |

### Compile
```bash
git clone https://github.com/niketdhale/autosar-idsm-toolkit.git
cd autosar-idsm-toolkit
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja
```
### Run CLI
```bash
./idsm_cli
```

### CLI Usage Examples
```bash
# 1. Initialize async manager & start background worker
init

# 2. Switch to normal driving mode (activates Run-mode monitors)
mode run

# 3. Simulate detector violation (returns instantly, processed async)
report mon=0x001 evt=0x100 sev=2 pay=0xDEADBEEF

# 4. Query monitor status
status 0x001

# 5. Force flush buffered events (bypasses flood protection)
flush 0x001

# 6. Graceful shutdown (stops worker, joins thread, clears state)
quit
```
## AUTOSAR Compliance Notes

| Specification Requirement | Implementation Status | Notes |
| :--- | :---: | :--- |
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
