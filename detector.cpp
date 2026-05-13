#include <iostream>
#include <fstream>
#include <string>
#include <map>

using namespace std;

string toLower(string s) {
    for(int i = 0; i < s.length(); i++) {
        if(s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = s[i] + 32;
        }
    }
    return s;
}

bool isFailedLogin(string line) {
    string low = toLower(line);
    return (low.find("failed") != string::npos ||
            low.find("failure") != string::npos ||
            low.find("invalid") != string::npos) &&
            (low.find("password") != string::npos ||
             low.find("login") != string::npos);
}

string extractIP(string line) {
    int start = -1;
    int dots = 0;
    
    for(int i = 0; i < line.length(); i++) {
        char c = line[i];
        if((c >= '0' && c <= '9') || c == '.') {
            if(start == -1) start = i;
            if(c == '.') dots++;
        } else {
            if(start != -1 && dots >= 3) {
                return line.substr(start, i - start);
            }
            start = -1;
            dots = 0;
        }
    }
    
    if(start != -1 && dots >= 3) {
        return line.substr(start);
    }
    return "unknown";
}

int main() {
    cout << "=== LOG ATTACK DETECTOR ===" << endl;
    cout << "Scanning for brute force attacks..." << endl << endl;
    
    string filename;
    cout << "Enter log file name: ";
    cin >> filename;
    
    ifstream logFile(filename);
    if(!logFile.is_open()) {
        cout << "Error: Cannot open " << filename << endl;
        return 1;
    }
    
    map<string, int> attackCount;
    string line;
    int totalLines = 0;
    
    while(getline(logFile, line)) {
        totalLines++;
        if(isFailedLogin(line)) {
            string ip = extractIP(line);
            attackCount[ip]++;
        }
    }
    logFile.close();
    
    cout << "Total lines scanned: " << totalLines << endl;
    
    int totalFails = 0;
    for(auto& pair : attackCount) {
        totalFails += pair.second;
    }
    cout << "Failed login attempts: " << totalFails << endl << endl;
    
    cout << "=== SUSPICIOUS IP ADDRESSES ===" << endl;
    int alertThreshold = 5;
    int flagged = 0;
    
    for(auto& pair : attackCount) {
        if(pair.second >= alertThreshold) {
            cout << "⚠️ IP: " << pair.first 
                 << " - " << pair.second << " attempts" << endl;
            flagged++;
        }
    }
    
    if(flagged == 0) {
        cout << "No suspicious activity detected" << endl;
    } else {
        cout << endl << "=== ACTION REQUIRED ===" << endl;
        cout << "Block these IPs immediately." << endl;
    }
    
    return 0;
}
