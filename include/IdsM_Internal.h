#pragma once
#include "IdsM_Types.h"

#ifdef __cplusplus

#include <vector>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>
#include <condition_variable>

/* Internal event buffer entry */
struct IdsM_InternalEvent {
    IdsM_EventReportType report;
    uint64_t first_seen_ns;
    uint32_t occurrence_count;
};

/* Internal monitor state */
struct IdsM_InternalMonitor {
    IdsM_MonitorConfigType config;
    IdsM_DetectionStatusType status;
    std::queue<IdsM_InternalEvent> event_buffer;
    uint64_t last_report_ns;
    boolean active;
};

/* Global manager state (singleton pattern) */
class IdsM_Manager {
public:
    static IdsM_Manager& Instance();
    
    /* Public API */
    STD_RETURN_TYPE Init(const IdsM_MonitorConfigType* config, uint16_t count);
    STD_RETURN_TYPE DeInit();
    STD_RETURN_TYPE SetOperatingMode(IdsM_OperatingModeType mode);
    IdsM_OperatingModeType GetOperatingMode() const;
    STD_RETURN_TYPE ReportEvent(const IdsM_EventReportType* event);
    IdsM_DetectionStatusType GetDetectionStatus(IdsM_MonitorIdType monitor_id);
    STD_RETURN_TYPE ResetDetectionStatus(IdsM_MonitorIdType monitor_id);
    uint32_t GetPendingEventCount(IdsM_MonitorIdType monitor_id);
    STD_RETURN_TYPE FlushEvents(IdsM_MonitorIdType monitor_id);
    void SetDemReportCallback(IdsM_DemReportCallback cb);
    void SetNvmStoreCallback(IdsM_NvmStoreCallback cb);
    
    /* Stats */
    struct Stats {
        uint32_t total_events_reported;
        uint32_t events_filtered_flood;
        uint32_t events_flushed_to_dem;
        uint32_t mode_transitions;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    IdsM_Manager() = default;
    ~IdsM_Manager() = default;
    IdsM_Manager(const IdsM_Manager&) = delete;
    IdsM_Manager& operator=(const IdsM_Manager&) = delete;
    
    /* --- ASYNC ENGINE --- */
    std::thread m_worker_thread;
    std::atomic<bool> m_worker_running{false};
    std::condition_variable m_queue_cv;
    std::queue<IdsM_EventReportType> m_incoming_queue; // Async event queue
    
    /* --- STATE --- */
    mutable std::mutex m_mutex;
    IdsM_OperatingModeType m_current_mode;
    std::unordered_map<IdsM_MonitorIdType, IdsM_InternalMonitor> m_monitors;
    IdsM_DemReportCallback m_dem_cb;
    IdsM_NvmStoreCallback m_nvm_cb;
    Stats m_stats;
    
    /* Helpers */
    bool isMonitorEnabledInMode(const IdsM_InternalMonitor& mon) const;
    bool isFloodProtected(const IdsM_InternalMonitor& mon, uint64_t now_ns) const;
    void forwardToDem(const IdsM_EventReportType& event);
    uint64_t getTimestampNs() const;
    void worker_loop(); /* Background thread entry point */
};

#endif /* __cplusplus */