#include "../../include/IdsM.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdio> // Add this at top of main.cpp

static void dem_callback(const IdsM_EventReportType* event) {
    // fprintf(stderr, ...) is atomic and unbuffered across threads
    fprintf(stderr, "[DEM] Event Reported | Monitor=0x%X Event=0x%X Severity=%d Payload=0x%X\n",
            event->monitor_id, event->event_id, event->severity, event->payload);
}

int main() {
    std::cout << "=== AUTOSAR IDSM Simulator (Async) ===\n"
              << "Commands: init, mode <pre|run|post>, report, status, flush, quit\n";

    bool initialized = false;
    
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit") break;
        
        else if (cmd == "init") {
            IdsM_MonitorConfigType configs[1] = {
                {0x001, 10, 100, IDSM_SEVERITY_MEDIUM, true, true, false}
            };
            if (IdsM_Init(configs, 1) == E_OK) {
                IdsM_SetDemReportCallback(dem_callback);
                initialized = true;
                std::cout << "[IDSM] Initialized | Async Engine Running\n";
            } else {
                std::cout << "[IDSM ERR] Init failed\n";
            }
        }
        else if (cmd == "mode" && initialized) {
            std::string mode_str; iss >> mode_str;
            IdsM_OperatingModeType mode;
            if (mode_str == "pre") mode = IDSM_PRE_RUN_MODE;
            else if (mode_str == "run") mode = IDSM_RUN_MODE;
            else if (mode_str == "post") mode = IDSM_POST_RUN_MODE;
            else { std::cout << "[ERR] Usage: mode <pre|run|post>\n"; continue; }
            
            if (IdsM_SetOperatingMode(mode) == E_OK) {
                std::cout << "[IDSM] Mode set to " << mode_str << "\n";
            } else {
                std::cout << "[IDSM ERR] Mode change failed\n";
            }
        }
        else if (cmd == "report" && initialized) {
            IdsM_EventReportType evt{};
            std::string param;
            while (iss >> param) {
                auto eq = param.find('=');
                if (eq == std::string::npos) continue;
                std::string k = param.substr(0, eq);
                std::string v = param.substr(eq + 1);
                if (k == "mon") evt.monitor_id = std::stoul(v, nullptr, 16);
                else if (k == "evt") evt.event_id = std::stoul(v, nullptr, 16);
                else if (k == "sev") evt.severity = static_cast<IdsM_EventSeverityType>(std::stoul(v));
                else if (k == "pay") evt.payload = std::stoul(v, nullptr, 16);
            }
            evt.timestamp_ms = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count() % 100000);
            
            if (IdsM_ReportEvent(&evt) == E_OK) {
                std::cout << "[IDSM] Event Queued | Monitor=0x" << std::hex << evt.monitor_id << std::dec << "\n";
            } else {
                std::cout << "[IDSM ERR] Queue failed (check config/mode)\n";
            }
        }
        else if (cmd == "status" && initialized) {
            uint16 mon_id; iss >> std::hex >> mon_id;
            auto status = IdsM_GetDetectionStatus(mon_id);
            const char* status_str = status == IDSM_STATUS_OK ? "OK" : 
                                    status == IDSM_STATUS_VIOLATION ? "VIOLATION" : "UNINIT";
            std::cout << "[IDSM] Monitor 0x" << std::hex << mon_id << std::dec 
                      << " Status=" << status_str << "\n";
        }
        else if (cmd == "flush" && initialized) {
            uint16 mon_id; iss >> std::hex >> mon_id;
            if (IdsM_FlushEvents(mon_id) == E_OK) {
                std::cout << "[IDSM] Events flushed to DEM\n";
            }
        }
        else {
            std::cout << "[?] Unknown command or not initialized\n";
        }
    }
    if (initialized) IdsM_DeInit();
    std::cout << "Shutdown complete.\n";
    return 0;
}