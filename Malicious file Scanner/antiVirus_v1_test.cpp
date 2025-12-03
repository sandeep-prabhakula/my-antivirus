#include <iostream>
#include <fstream>
#include <filesystem>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <bits/stdc++.h>
#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>

using namespace std;
namespace fs = std::filesystem;

long getSimilarity(std::string hash){
    Py_Initialize();
    PyObject* sysPath = PySys_GetObject("path");
    PyList_Append(sysPath, PyUnicode_FromString("/home/sandeep/Coding/cppTutorials/Antivirus/Malicious file Scanner"));
    PyObject* moduleName = PyUnicode_FromString("similaritySearch");
    PyObject* module = PyImport_Import(moduleName);
    Py_DECREF(moduleName);
    if (!module) {
        PyErr_Print();
        std::cerr << "Error: could not import module\n";
        return 1;
    }

    PyObject* func = PyObject_GetAttrString(module, "findSimilarity");

    if (!func || !PyCallable_Check(func)) {
        PyErr_Print();
        std::cerr << "Error: function not found or not callable\n";
        return 1;
    }
    
    PyObject* args = PyTuple_Pack(1, PyUnicode_FromString(hash.c_str()));
    PyObject* result = PyObject_CallObject(func, args);
    long value = PyLong_AsLong(result);
    if (result) {
        long value = PyLong_AsLong(result);
        std::cout << "Result from Python: " << value << "\n";
        Py_DECREF(result);
    } else {
        PyErr_Print();
    }

    // Cleanup
    Py_DECREF(args);
    Py_DECREF(func);
    Py_DECREF(module);
    Py_Finalize();
    
    return value;
}


unordered_set<string> loadSignatures(const string& sigPath, unordered_set<string> signatures) {
    // unordered_set<string> signatures;
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

int main(int argc, char* argv[]){
    
    ofstream out("malwarePaths.txt");
    // ofstream hashes("hashes.txt");
    ofstream fileSigns("fileSigns.txt");
    ofstream pathOut("pathsScanned.txt");
    
    if(argc==1){
        cout<< "Provide path to scan in.!!!"<<endl;
        return 0;
    }
    cout<< "Path selected for scan: "<< argv[1]<< endl;
    // unordered_set<string> signatures;
    // signatures = loadSignatures("eicar.txt",signatures);
    // for(const auto& entry: fs::recursive_directory_iterator("/home/sandeep/Coding/cppTutorials/Antivirus/Malicious file Scanner/MD5")){
    //     if(fs::is_regular_file(entry)){
    //         string path = entry.path().string();
    //         signatures = loadSignatures(path,signatures);
    //     }
    // }
    // for(const auto& entry: fs::recursive_directory_iterator("/home/sandeep/Coding/cppTutorials/Antivirus/Malicious file Scanner/SHA1")){
    //     if(fs::is_regular_file(entry)){
    //         string path = entry.path().string();
    //         signatures = loadSignatures(path,signatures);
    //     }
    // }
    // for(const auto& entry: fs::recursive_directory_iterator("/home/sandeep/Coding/cppTutorials/Antivirus/Malicious file Scanner/SHA256")){
    //     if(fs::is_regular_file(entry)){
    //         string path = entry.path().string();
    //         signatures = loadSignatures(path,signatures);
    //     }
    // }
    
    // cout<<"Loaded signatures"<<endl;

    // for(const auto hash: signatures)
    //     hashes<< hash <<endl;
    int count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(argv[1])) {
        if (fs::is_regular_file(entry)) {
            string path = entry.path().string();
            auto hash = computeSHA256(path);
            fileSigns<< hash <<endl;
            count++;
            // pathOut<<"Scan completed: "<<path <<endl;
            
            // !-- the below code is checking the equality check
            // if (signatures.find(hash) != signatures.end()) {
            //     out << "[!] Malware detected: " << path << endl;
            // }
            long resp = getSimilarity(hash);
            if(resp){
                out << "[!] Malware detected: " << path << endl;
            }
        }
    }
    cout<<"Files found: "<<count<<endl;
}
