#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>

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

// Stores information from one parsed log
struct LogEntry {
    Status status;
    std::string ip;
    std::string raw;
    bool valid;
};

// Function declaration
LogEntry parseLog(const std::string& line);
ThreatLevel calculateThreat(int failures);
std::string threatToString(ThreatLevel level);

// Counts log results
void analyzeLogs(const std::vector<LogEntry>& logs, int& alerts, int& successes, int& unknowns, int& invalids) {
    alerts = successes = unknowns = invalids = 0;
    for (const auto& log : logs) {
        if (!log.valid) {
            invalids++;
            continue;
        }
        if (log.status == FAILED) {
            alerts++;
        }
        else if (log.status == SUCCESS) {
            successes++;
        }
        else {
            unknowns++;
        }
    }
}

// Main program
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
    int alerts = 0;
    int successes = 0;
    int unknowns = 0;
    int invalids = 0;
    analyzeLogs(logs, alerts, successes, unknowns, invalids);
// Count failed attempts by IP address
    std::map<std::string, int> failedIPs;
    for (const auto& log : logs) {
        if (log.status == FAILED) {
            failedIPs[log.ip]++;
        }
    }
// Display loaded logs
    std::cout << "\nLOGS LOADED\n";
    for (const auto& log : logs) {
        std::cout << log.raw << "\n";
    }
// Display overall log report
    std::cout << "\nLOG REPORT\n";
    std::cout << "Alerts = " << alerts << "\n";
    std::cout << "Successes = " << successes << "\n";
    std::cout << "Unknowns = " << unknowns << "\n";
    std::cout << "Invalids = " << invalids << "\n";
// Display failed IP report
    std::cout << "\nFAILED IP REPORT\n";
    for (const auto& ip : failedIPs) {
        ThreatLevel level = calculateThreat(ip.second);
        std::cout << ip.first << " = " << ip.second << " failures [" << threatToString(level) << "]\n";
    }
}

// Converts a raw log line into a LogEntry object
LogEntry parseLog(const std::string& line) {
    LogEntry entry;
// Default values
    entry.status = UNKNOWN;
    entry.valid = true;
    entry.raw = line;
    entry.ip = "";
// Find first separator
    size_t first = line.find(DELIM);
    if (first == std::string::npos) {
        entry.valid = false;
        return entry;
    }
// Find second separator
    size_t second = line.find(DELIM, first + DELIM.length());
    if (second == std::string::npos) {
        entry.valid = false;
        return entry;
    }
// Extract status section
    std::string statusStr = line.substr(first + DELIM.length(), second - (first + DELIM.length()));
// Convert text status into enum
    if (statusStr == "FAILED") {
        entry.status = FAILED;
    }
    else if (statusStr == "SUCCESS") {
        entry.status = SUCCESS;
    }
    else {
        entry.status = UNKNOWN;
    }
// Extract IP address
    entry.ip = line.substr(second + DELIM.length());
    return entry;
}

// Determines threat level based on failed attempts
ThreatLevel calculateThreat(int failures) {
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