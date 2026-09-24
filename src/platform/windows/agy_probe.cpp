#include "platform.h"

#include "diagnostics.h"
#include "http_client.h"

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

static std::vector<DWORD> agy_process_ids() {
    std::vector<DWORD> ids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return ids;
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, "agy.exe") == 0 || _stricmp(entry.szExeFile, "agy") == 0) ids.push_back(entry.th32ProcessID);
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return ids;
}

static std::vector<unsigned short> agy_listening_ports(const std::vector<DWORD>& ids) {
    std::vector<unsigned short> ports;
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return ports;
    std::vector<unsigned char> buffer(size);
    auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return ports;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_LISTEN) continue;
        bool owned = false;
        for (DWORD id : ids) if (row.dwOwningPid == id) owned = true;
        if (!owned || (row.dwLocalAddr != 0 && row.dwLocalAddr != htonl(INADDR_LOOPBACK))) continue;
        ports.push_back(ntohs(static_cast<u_short>(row.dwLocalPort)));
    }
    std::sort(ports.begin(), ports.end(), std::greater<unsigned short>());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

std::optional<std::string> fetch_agy_local_quota_summary() {
    const char* csrf = std::getenv("ANTIGRAVITY_CSRF_TOKEN");
    if (!csrf || !*csrf) csrf = std::getenv("LLM_USAGE_TRAY_GEMINI_CSRF_TOKEN");
    if (!csrf || !*csrf) {
        // Without a CSRF token, local AGY rejects requests with 401 unauthenticated.
        // Skipping avoids probing other internal ports (such as the HTTPS gRPC port) and triggering TLS handshake warnings in the CLI.
        return std::nullopt;
    }

    std::vector<DWORD> ids = agy_process_ids();
    if (ids.empty()) return std::nullopt;
    std::vector<unsigned short> ports = agy_listening_ports(ids);
    const char* ls_addr = std::getenv("ANTIGRAVITY_LS_ADDRESS");
    if (ls_addr && *ls_addr) {
        std::string s(ls_addr);
        auto colon = s.rfind(':');
        if (colon != std::string::npos && colon + 1 < s.size()) {
            try {
                int p = std::stoi(s.substr(colon + 1));
                if (p > 0 && p <= 65535) {
                    ports.insert(ports.begin(), static_cast<unsigned short>(p));
                }
            } catch (...) {}
        }
    }
    diagnostics_log("agy local probe processes=" + std::to_string(ids.size()) + " ports=" + std::to_string(ports.size()));

    auto probe = [&](unsigned short port) -> std::optional<std::string> {
        std::string url = "http://127.0.0.1:" + std::to_string(port) + "/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary";
        try {
            std::map<std::string, std::string> headers = {
                {"Connect-Protocol-Version", "1"},
                {"User-Agent", "antigravity/cli/1.1.24 windows/amd64"},
                {"x-codeium-csrf-token", csrf},
            };
            HttpResponse response = http_post_json(url, "{}", headers);
            diagnostics_log("agy local probe url=" + url + " status=" + std::to_string(response.status) + " body_length=" + std::to_string(response.body.size()));
            if (response.status >= 200 && response.status < 300 && response.body.find("\"groups\"") != std::string::npos) {
                return response.body;
            }
            if (response.status == 401 || response.status == 403) {
                // The HTTP language server answered but rejected auth; stop probing further ports to avoid hitting the HTTPS/gRPC port.
                return std::string();
            }
        } catch (const std::exception& error) {
            diagnostics_log("agy local probe url=" + url + " error=" + error.what());
        }
        return std::nullopt;
    };

    for (unsigned short port : ports) {
        auto body = probe(port);
        if (body.has_value()) {
            if (body->empty()) {
                // Auth error encountered on the HTTP port; stop probing
                return std::nullopt;
            }
            diagnostics_log("agy local probe selected_http_port=" + std::to_string(port));
            return body;
        }
    }
    return std::nullopt;
}
