#include <iostream>
#include <fstream>
#include <filesystem>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <bits/stdc++.h>
using namespace std;
namespace fs = std::filesystem;


unordered_set<string> loadSignatures(const string& sigPath) {
    unordered_set<string> signatures;
    ifstream sigFile(sigPath);
    string line;
    while (getline(sigFile, line)) {
        signatures.insert(line);
    }
    cout<<"Signatures found: "<<signatures.size()<<endl;
    return signatures;
}

string computeSHA256(const string& path) {
    ifstream file(path, std::ios::binary);
    if (!file) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    const EVP_MD* md = EVP_sha256();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }
    if (file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream hexStream;
    for (unsigned int i = 0; i < lengthOfHash; ++i)
        hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);

    return hexStream.str();
}

int main(){
    
    ofstream out("malwarePaths.txt");
    ofstream pathOut("pathsScanned.txt");
    // string st2 = " Very good";
    // out<<st2;

    // string st3 ;
    // ifstream in("dummy.txt");
    // in>>st3;
    // cout<<st3;
    
    
    // vector<int> v;
    // v.push_back(1);

    auto signatures = loadSignatures("eicar.txt");
    cout<<"Loaded signatures"<<endl;
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator("/home/sandeep/")) {
        if (fs::is_regular_file(entry)) {
            string path = entry.path().string();
            auto hash = computeSHA256(path);
            count++;
            pathOut<<"Scan completed: "<<path <<endl;
            if (signatures.find(hash) != signatures.end()) {
                out << "[!] Malware detected: " << path << endl;
            }
        }
    }
    cout<<"Files Scanned: "<<count<<endl;
}
