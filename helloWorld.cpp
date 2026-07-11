#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

// Separates parts of each log entry
const std::string DELIM = " - ";

// Represents the result of a single log
enum Status {
    FAILED,
    SUCCESS,
    UNKNOWN
};

// Represents the severity level of detected activity
enum ThreatLevel {
    NORMAL,
    SUSPICIOUS,
    ALERT,
    CRITICAL
};

// Represents the type of activity detected
enum Action {
    LOGIN,
    PORT_SCAN,
    FILE_ACCESS,
    UNKNOWN_ACTION
};

// Stores information from one parsed log
struct LogEntry {
    Action action;
    Status status;
    std::string ip;
    bool valid;
};

// Stores prioritised threat information for an IP
struct PriorityEntry {
    std::string ip;
    int failures;
    Action primaryAction;
    int threatScore;
    ThreatLevel level;
    std::string reason;
};

// Function declaration
LogEntry parseLog(const std::string& line);
ThreatLevel calculateThreat(int failures, Action action);
std::string threatToString(ThreatLevel level);
std::string actionToString(Action action);
int calculateThreatScore(int failures, Action action);
std::string generateThreatReason(int failures, Action action);

// Counts log results
void analyzeLogs(const std::vector<LogEntry>& logs, int& failures, int& successes, int& unknowns, int& invalids) {
    failures = successes = unknowns = invalids = 0;
    for (const auto& log : logs) {
        if (!log.valid) {
            invalids++;
            continue;
        }
        if (log.status == FAILED) {
            failures++;
        }
        else if (log.status == SUCCESS) {
            successes++;
        }
        else {
            unknowns++;
        }
    }
}

// Main program execution
int main() {
// Read logs from file
    std::string line;
    std::ifstream file("logs.txt");
    if (!file) {
        std::cout << "Could not open file.\n";
        return 1;
    }
// Store parsed logs
    std::vector<LogEntry> logs;
    while (std::getline(file, line)) {
        LogEntry entry = parseLog(line);
        logs.push_back(entry);
    }
    file.close();
// Store log analysis results
    int failures = 0;
    int successes = 0;
    int unknowns = 0;
    int invalids = 0;
    analyzeLogs(logs, failures, successes, unknowns, invalids);
    std::map<Action, int> actionCounts;
    for (const auto& log : logs) {
        if (!log.valid) {
            continue;
        }
        actionCounts[log.action]++;
    }
// Store failed actions grouped by IP address
    std::map<std::string, std::map<Action, int>> ipActions;
    for (const auto& log : logs) {
        if (!log.valid) {
            continue;
        }
        if (log.status == FAILED) {
            ipActions[log.ip][log.action]++;
        }
    }
    int totalLogs = logs.size();
    int validLogs = totalLogs - invalids;
// Count failed attempts by IP address
    std::map<std::string, int> failedIPs;
    for (const auto& log : logs) {
        if (log.valid && log.status == FAILED) {
            failedIPs[log.ip]++;
        }
    }
// Create prioritised threat entries from failed IP addresses
    std::vector<PriorityEntry> priorityList;
    for (const auto& ip : failedIPs) {
        PriorityEntry entry;
        entry.ip = ip.first;
        entry.failures = ip.second;
        int highestCount = 0;
        Action commonAction = UNKNOWN_ACTION;
        for (const auto& actionCount : ipActions[ip.first]) {
            if (actionCount.second > highestCount) {
                highestCount = actionCount.second;
                commonAction = actionCount.first;
            }
        }
        entry.primaryAction = commonAction;
        entry.level = calculateThreat(ip.second, entry.primaryAction);
// Calculate numerical threat score and generate explanation
        entry.threatScore = calculateThreatScore(ip.second, entry.primaryAction);
        entry.reason = generateThreatReason(ip.second, entry.primaryAction);
        priorityList.push_back(entry);
    }
// Sort threats by severity, failure count, then IP address
    auto compareThreatScore = [](const PriorityEntry& first, const PriorityEntry& second) {
        if (first.threatScore != second.threatScore) {
            return first.threatScore > second.threatScore;
        }
        if (first.failures != second.failures) {
            return first.failures > second.failures;
        }
        return first.ip < second.ip;
    };
    std::sort(priorityList.begin(), priorityList.end(), compareThreatScore);
// Display log analysis report
    std::cout << "\n==================================================\n"
              << "               LOG ANALYSIS REPORT\n"
              << "==================================================\n\n";
    std::cout << "[ FILE STATISTICS ]\n\n"
              << "Logs Processed : " << totalLogs << "\n"
              << "Valid Logs     : " << validLogs << "\n"
              << "Invalid Logs   : " << invalids << "\n\n";
    std::cout << "[ EVENT SUMMARY ]\n\n"
              << "Failed Events  : " << failures << "\n"
              << "Successful     : " << successes << "\n"
              << "Unknown Events : " << unknowns << "\n\n";
    std::cout << "LOGIN         : " << actionCounts[LOGIN] << "\n"
              << "PORT_SCAN     : " << actionCounts[PORT_SCAN] << "\n"
              << "FILE_ACCESS   : " << actionCounts[FILE_ACCESS] << "\n"
              << "UNKNOWN_ACTION: " << actionCounts[UNKNOWN_ACTION] << "\n\n";
    std::cout << "[ THREAT REPORT ]\n\n";
    for (const auto& entry : priorityList) {
        std::cout << "IP Address      : " << entry.ip << "\n"
                  << "Failed Attempts : " << entry.failures << "\n"
                  << "Primary Action  : " << actionToString(entry.primaryAction) << "\n"
                  << "Threat Score    : " << entry.threatScore << "\n"
                  << "Threat Level    : " << threatToString(entry.level) << "\n"
                  << "Reason          : " << entry.reason << "\n"
                  << "--------------------------------------------------\n\n";
    }
    std::cout << "==================================================\n";
    return 0;
}

// Converts a raw log line into a LogEntry object
LogEntry parseLog(const std::string& line) {
    LogEntry entry;
    entry.status = UNKNOWN;
    entry.action = UNKNOWN_ACTION;
    entry.valid = true;
    size_t first = line.find(DELIM);
    if (first == std::string::npos) {
        entry.valid = false;
        return entry;
    }
    size_t second = line.find(DELIM, first + DELIM.length());
    if (second == std::string::npos) {
        entry.valid = false;
        return entry;
    }
    size_t third = line.find(DELIM, second + DELIM.length());
    if (third == std::string::npos) {
        entry.valid = false;
        return entry;
    }
    std::string actionStr = line.substr(first + DELIM.length(), second - (first + DELIM.length()));
    std::string statusStr = line.substr(second + DELIM.length(), third - (second + DELIM.length()));
    entry.ip = line.substr(third + DELIM.length());
    if (statusStr == "FAILED") {
        entry.status = FAILED;
    }
    else if (statusStr == "SUCCESS") {
        entry.status = SUCCESS;
    }
    if (actionStr == "LOGIN") {
        entry.action = LOGIN;
    }
    else if (actionStr == "PORT_SCAN") {
        entry.action = PORT_SCAN;
    }
    else if (actionStr == "FILE_ACCESS") {
        entry.action = FILE_ACCESS;
    }
    return entry;
}

// Determines threat level based on failed attempts and action type
ThreatLevel calculateThreat(int failures, Action action) {
    if (action == PORT_SCAN) {
        if (failures >= 5) {
            return CRITICAL;
        }
        else if (failures >= 3) {
            return ALERT;
        }
        else {
            return SUSPICIOUS;
        }
    }
    else if (action == FILE_ACCESS) {
        if (failures >= 6) {
            return CRITICAL;
        }
        else if (failures >= 3) {
            return ALERT;
        }
        else {
            return SUSPICIOUS;
        }
    }
    else if (action == LOGIN) {
        if (failures >= 10) {
            return CRITICAL;
        }
        else if (failures >= 6) {
            return ALERT;
        }
        else if (failures >= 3) {
            return SUSPICIOUS;
        }
        else {
            return NORMAL;
        }
    }
    else {
        if (failures >= 5) {
            return ALERT;
        }
        else if (failures >= 3) {
            return SUSPICIOUS;
        }
        else {
            return NORMAL;
        }
    }
    return NORMAL;
}

// Converts threat level enum to readable text
std::string threatToString(ThreatLevel level) {
    if (level == NORMAL) {
        return "NORMAL";
    }
    else if (level == SUSPICIOUS) {
        return "SUSPICIOUS";
    }
    else if (level == ALERT) {
        return "ALERT";
    }
    else {
        return "CRITICAL";
    }
}

// Converts action enum to readable text
std::string actionToString(Action action) {
    if (action == LOGIN) {
        return "LOGIN";
    }
    else if (action == PORT_SCAN) {
        return "PORT_SCAN";
    }
    else if (action == FILE_ACCESS) {
        return "FILE_ACCESS";
    }
    else {
        return "UNKNOWN_ACTION";
    }
}

// Calculates threat score based on failures and action type
int calculateThreatScore(int failures, Action action) {
    int score = failures * 10;
    if (action == PORT_SCAN) {
        score += 20;
    }
    else if (action == FILE_ACCESS) {
        score += 15;
    }
    else if (action == LOGIN) {
        score += 10;
    }
    return score;
}

// Generates reason for threat based on action type
std::string generateThreatReason(int failures, Action action) {
    if (action == PORT_SCAN) {
        return "Detected " + std::to_string(failures) + " failed port scan attempts";
    }
    else if (action == FILE_ACCESS) {
        return "Detected " + std::to_string(failures) + " failed file access attempts";
    }
    else if (action == LOGIN) {
        return "Detected " + std::to_string(failures) + " failed login attempts";
    }
    else {
        return "Detected " + std::to_string(failures) + " unknown activities";
    }
}