#include <cmath>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <bits/stdc++.h>
using namespace std;
namespace fs = std::filesystem;

ofstream out("paths.csv");
ofstream pathOut("pathsScanned.txt");

string readFile(const string& filePath) {
    ifstream file(filePath, std::ios::binary);
    if (!file) return "";

    return string((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
}

bool containsSuspiciousStrings(const string& data) {
    vector<string> indicators = {
        "CreateRemoteThread", "VirtualAllocEx", "powershell",
        "cmd.exe", "WriteProcessMemory", "system(", "exec(",
        "/bin/bash", "/bin/sh"
    };

    for (const auto& keyword : indicators) {
        if (data.find(keyword) != string::npos)
            return true;
    }

    return false;
}

double calculateEntropy(const string& data) {
    std::unordered_map<char, int> freq;
    for (char ch : data) {
        freq[ch]++;
    }

    double entropy = 0.0;
    for (const auto& pair : freq) {
        double p = static_cast<double>(pair.second) / data.size();
        entropy -= p * log2(p);
    }

    return entropy;
}

void scanFile(const fs::path& filePath) {
    string data = readFile(filePath);
    if (data.empty()) return;
    pathOut<<"Scan completed"<<filePath<<endl;
    double entropy = calculateEntropy(data);
    bool suspicious = containsSuspiciousStrings(data);

    if (entropy > 7.5 || suspicious) {
        // cout << "[!] Suspicious File: " << filePath << "\n";
        // cout << "    ↳ Entropy: " << entropy << ", Strings: " << (suspicious ? "Yes" : "No") << "\n";
        out<< "\"" << filePath.string() << "\","
                << entropy << ","
                << (suspicious ? "Yes" : "No") << "\n";
    }
}


void scanDirectory(const fs::path& root) {
    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        try {
            if (fs::is_regular_file(entry)) {
                scanFile(entry.path());
            }
        } catch (const std::exception& ex) {
            // Ignore unreadable files or permission errors
        }
    }
}


int main() {
#ifdef _WIN32
    std::cout << "[*] Starting scan on Windows: C:\\ \n";
    scanDirectory("C:\\");
#else
    std::cout << "[*] Starting scan on Linux: / \n";
    scanDirectory("/home");
#endif
    std::cout << "[✓] Scan completed.\n";
    return 0;
}