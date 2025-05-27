#include <cmath>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <yara.h>
#include <bits/stdc++.h>
using namespace std;
namespace fs = std::filesystem;

ofstream out("malwarePaths.txt");
ofstream pathOut("pathsScanned.txt");

int callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        std::string* matched_file = static_cast<std::string*>(user_data);
        std::cout << "[+] YARA match found in: " << *matched_file << std::endl;
    }
    return CALLBACK_CONTINUE;
}

void run_yara_on_file(const std::string& filepath, const std::string& rule_file) {
    YR_RULES* rules = nullptr;
    YR_COMPILER* compiler = nullptr;

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA" << std::endl;
        return;
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "Failed to create YARA compiler" << std::endl;
        yr_finalize();
        return;
    }

    FILE* rule_fp = fopen(rule_file.c_str(), "r");
    if (!rule_fp) {
        std::cerr << "Failed to open rule file: " << rule_file << std::endl;
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    yr_compiler_add_file(compiler, rule_fp, nullptr, rule_file.c_str());
    fclose(rule_fp);

    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    std::string file_path_copy = filepath;
    int result = yr_rules_scan_file(
        rules, filepath.c_str(), 0, callback, &file_path_copy, 0
    );

    if (result != ERROR_SUCCESS) {
        std::cerr << "Scan failed on: " << filepath << std::endl;
    }

    yr_rules_destroy(rules);
    yr_finalize();
}

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
        out<<filePath.string()<<endl;
        // out<< "\"" << filePath.string() << "\","
        //         << entropy << ","
        //         << (suspicious ? "Yes" : "No") << "\n";
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
    string ruleFile = "mix.yar";
    ifstream readFilePaths("malwarePaths.txt");
#ifdef _WIN32
    std::cout << "[*] Starting scan on Windows: C:\\ \n";
    scanDirectory("C:\\");
#else
    std::cout << "[*] Starting scan on Linux: / \n";
    scanDirectory("/home/sandeep/cppTutorials");
    vector<string>paths;
    string line;
    while(std::getline(readFilePaths,line)){
        paths.push_back(line);
    }
    std::cout<< "[*] Validating Malicious files"<<endl;
    for (const auto &path:paths){
        run_yara_on_file(path, ruleFile);
    }

#endif
    std::cout << "[✓] Scan completed.\n";
    return 0;
}