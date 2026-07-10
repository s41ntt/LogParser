#include <iostream>
#include <fstream>
#include <string>
#include <vector>

const std::string DELIM = " - ";

enum Status {
    FAILED,
    SUCCESS,
    UNKNOWN
};

struct logEntry {
    Status status;
    std::string ip;
    std::string raw;
    bool valid;
};

logEntry parseLog(const std::string& line);

void analyzeLogs(const std::vector<logEntry>& logs, int& alerts, int& successes, int& unknowns, int& invalids) {
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

int main() {
    std::string line;
    std::ifstream file("logs.txt");
    if (!file) {
        std::cout << "Could not open file.\n";
        return 1;
    }
    std::vector<logEntry> logs;
    while (std::getline(file, line)) {
        logEntry entry = parseLog(line);
        logs.push_back(entry);
    }
    file.close();
    int alerts = 0;
    int successes = 0;
    int unknowns = 0;
    int invalids = 0;
    analyzeLogs(logs, alerts, successes, unknowns, invalids);
    std::cout << "\nLOGS LOADED\n";
    for (const auto& log : logs) {
        std::cout << log.raw << "\n";
    }
    std::cout << "\nLOG REPORT\n";
    std::cout << "Alerts = " << alerts << "\n";
    std::cout << "Successes = " << successes << "\n";
    std::cout << "Unknowns = " << unknowns << "\n";
    std::cout << "Invalids = " << invalids << "\n";
}

logEntry parseLog(const std::string& line) {
    logEntry entry;
    entry.status = UNKNOWN;
    entry.valid = true;
    entry.raw = line;
    entry.ip = "";
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
    std::string statusStr = line.substr(first + DELIM.length(), second - (first + DELIM.length()));
    if (statusStr == "FAILED") {
        entry.status = FAILED;
    }
    else if (statusStr == "SUCCESS") {
        entry.status = SUCCESS;
    }
    else {
        entry.status = UNKNOWN;
    }
    entry.ip = line.substr(second + DELIM.length());
    return entry;
}