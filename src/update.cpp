#include "update.h"

#include "diagnostics.h"
#include "http_client.h"
#include "json_util.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <signal.h>
#include <unistd.h>
#else
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace {

constexpr const char* kLatestMetadataUrl = "https://github.com/MorenoLand/Moreno.UsageTray/releases/latest/download/latest.json";

std::filesystem::path executable_path() {
#if defined(_WIN32)
    std::string value(32768, '\0');
    DWORD length = GetModuleFileNameA(nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (length > 0 && length < value.size()) {
        value.resize(length);
        return std::filesystem::path(value);
    }
#elif defined(__APPLE__)
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) == -1 && size > 0) {
        std::string value(size + 1, '\0');
        if (_NSGetExecutablePath(value.data(), &size) == 0) return std::filesystem::path(value.c_str());
    }
#else
    std::string value(PATH_MAX, '\0');
    ssize_t length = readlink("/proc/self/exe", value.data(), value.size() - 1);
    if (length > 0) {
        value.resize(static_cast<std::size_t>(length));
        return std::filesystem::path(value);
    }
#endif
    std::error_code error;
    return std::filesystem::current_path(error) / "LLMUsageTray";
}

struct Sha256 {
    std::array<std::uint32_t, 8> state{};
    std::array<std::uint8_t, 64> block{};
    std::size_t block_size = 0;
    std::uint64_t bit_count = 0;

    static std::uint32_t rotate_right(std::uint32_t value, std::uint32_t count) {
        return (value >> count) | (value << (32 - count));
    }

    void transform() {
        static constexpr std::uint32_t k[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        std::uint32_t words[64]{};
        for (std::size_t i = 0; i < 16; ++i) words[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) | (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) | (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) | block[i * 4 + 3];
        for (std::size_t i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotate_right(words[i - 15], 7) ^ rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3);
            std::uint32_t s1 = rotate_right(words[i - 2], 17) ^ rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            std::uint32_t choose = (e & f) ^ (~e & g);
            std::uint32_t temp1 = h + s1 + choose + k[i] + words[i];
            std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t temp2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    Sha256() : state{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

    void update(const std::uint8_t* data, std::size_t size) {
        for (std::size_t i = 0; i < size; ++i) {
            block[block_size++] = data[i];
            if (block_size == block.size()) {
                transform();
                bit_count += 512;
                block_size = 0;
            }
        }
    }

    std::string final() {
        bit_count += static_cast<std::uint64_t>(block_size) * 8;
        block[block_size++] = 0x80;
        if (block_size > 56) {
            while (block_size < block.size()) block[block_size++] = 0;
            transform();
            block_size = 0;
        }
        while (block_size < 56) block[block_size++] = 0;
        for (int i = 7; i >= 0; --i) block[block_size++] = static_cast<std::uint8_t>(bit_count >> (i * 8));
        transform();
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (std::uint32_t value : state) out << std::setw(8) << value;
        return out.str();
    }
};

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::array<int, 3> version_parts(const std::string& value) {
    std::array<int, 3> parts{};
    if (value.empty()) return parts;
    std::size_t start = value[0] == 'v' ? 1 : 0;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        std::size_t end = value.find('.', start);
        std::string piece = value.substr(start, end == std::string::npos ? std::string::npos : end - start);
        try { parts[i] = std::stoi(piece); } catch (...) { return {}; }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return parts;
}

int compare_versions(const std::string& left, const std::string& right) {
    auto a = version_parts(left);
    auto b = version_parts(right);
    for (std::size_t i = 0; i < a.size(); ++i) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

const char* platform_suffix() {
#if defined(_WIN32)
    return "windows_x64";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux_x64";
#endif
}

#if defined(_WIN32)
std::wstring widen(const std::string& value) {
    if (value.empty()) return L"";
    int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), length);
    return result;
}

std::wstring quote_argument(const std::filesystem::path& path) {
    return L"\"" + widen(path.string()) + L"\"";
}

std::wstring quote_argument(const std::string& value) {
    return L"\"" + widen(value) + L"\"";
}

bool write_windows_helper(const std::filesystem::path& script) {
    std::ofstream out(script, std::ios::trunc);
    if (!out) return false;
    out << "$stage = $args[0]\n";
    out << "$target = $args[1]\n";
    out << "$expected = $args[2].ToLowerInvariant()\n";
    out << "$parent = [int]$args[3]\n";
    out << "try { Wait-Process -Id $parent -Timeout 60 -ErrorAction SilentlyContinue } catch {}\n";
    out << "for ($i = 0; $i -lt 240; $i++) {\n";
    out << "  try {\n";
    out << "    if (!(Test-Path -LiteralPath $stage)) { exit 2 }\n";
    out << "    $actual = (Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash.ToLowerInvariant()\n";
    out << "    if ($actual -ne $expected) { exit 3 }\n";
    out << "    Move-Item -LiteralPath $stage -Destination $target -Force -ErrorAction Stop\n";
    out << "    if (Test-Path -LiteralPath $target) {\n";
    out << "      Start-Process -FilePath $target\n";
    out << "      Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue\n";
    out << "      exit 0\n";
    out << "    }\n";
    out << "  } catch {}\n";
    out << "  Start-Sleep -Milliseconds 250\n";
    out << "}\n";
    out << "exit 4\n";
    return static_cast<bool>(out);
}
#endif

} // namespace

std::filesystem::path current_executable_path() {
    return executable_path();
}

std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return "";
    Sha256 hash;
    std::array<std::uint8_t, 8192> buffer{};
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize count = input.gcount();
        if (count > 0) hash.update(buffer.data(), static_cast<std::size_t>(count));
    }
    return hash.final();
}

std::optional<UpdateInfo> check_for_update() {
    HttpResponse response = http_get(kLatestMetadataUrl, {{"Accept", "application/json"}});
    diagnostics_log("update metadata status=" + std::to_string(response.status) + " body_length=" + std::to_string(response.body.size()));
    if (response.status < 200 || response.status >= 300) throw std::runtime_error("Update metadata request failed: HTTP " + std::to_string(response.status));
    std::string version = json_string(response.body, "version").value_or("");
    if (version.empty()) throw std::runtime_error("Update metadata missing version");
    std::string suffix = platform_suffix();
    UpdateInfo info;
    info.version = version;
    info.sha256 = json_string(response.body, suffix + "_binary_sha256").value_or(json_string(response.body, suffix + "_sha256").value_or(""));
    info.asset_url = json_string(response.body, suffix + "_binary_url").value_or(json_string(response.body, suffix + "_url").value_or(""));
    info.release_url = json_string(response.body, "release_url").value_or("https://github.com/MorenoLand/Moreno.UsageTray/releases/latest");
    if (info.asset_url.empty() || info.sha256.empty()) throw std::runtime_error("Update metadata missing platform binary");
    std::string current_hash = sha256_file(current_executable_path());
    bool version_newer = compare_versions(info.version, LLM_USAGE_TRAY_VERSION) > 0;
    bool hash_mismatch = !current_hash.empty() && lower_ascii(info.sha256) != lower_ascii(current_hash);
    diagnostics_log("update metadata version=" + info.version + " current=" + LLM_USAGE_TRAY_VERSION + " hash_mismatch=" + std::string(hash_mismatch ? "true" : "false"));
    if (!version_newer && !(compare_versions(info.version, LLM_USAGE_TRAY_VERSION) == 0 && hash_mismatch)) return std::nullopt;
    return info;
}

std::filesystem::path download_update(const UpdateInfo& info, const UpdateProgressCallback& progress) {
    std::filesystem::path target = current_executable_path();
    std::filesystem::path staged = target;
    staged += ".update";
    std::error_code error;
    std::filesystem::remove(staged, error);
    HttpProgressCallback http_progress = [&](std::size_t received, std::size_t total) {
        if (progress && total > 0) progress(std::clamp(static_cast<double>(received) / static_cast<double>(total), 0.0, 1.0));
    };
    HttpResponse response = http_get(info.asset_url, {{"Accept", "application/octet-stream"}}, http_progress);
    diagnostics_log("update download status=" + std::to_string(response.status) + " body_length=" + std::to_string(response.body.size()));
    if (response.status < 200 || response.status >= 300) throw std::runtime_error("Update download failed: HTTP " + std::to_string(response.status));
    std::ofstream out(staged, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Unable to create update staging file");
    out.write(response.body.data(), static_cast<std::streamsize>(response.body.size()));
    out.close();
    if (!out) throw std::runtime_error("Unable to write update staging file");
    if (progress) progress(1.0);
    std::string actual = sha256_file(staged);
    if (actual.empty() || lower_ascii(actual) != lower_ascii(info.sha256)) {
        std::filesystem::remove(staged, error);
        throw std::runtime_error("Update SHA-256 verification failed");
    }
    return staged;
}

bool launch_update_helper(const std::filesystem::path& staged, const std::filesystem::path& target, const std::string& sha256) {
#if defined(_WIN32)
    std::filesystem::path script = staged;
    script += ".ps1";
    if (!write_windows_helper(script)) return false;
    std::wstring command = L"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " + quote_argument(script) + L" " + quote_argument(staged) + L" " + quote_argument(target) + L" " + quote_argument(sha256) + L" " + std::to_wstring(GetCurrentProcessId());
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    BOOL created = CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    if (!created) {
        diagnostics_log("update helper launch failed");
        return false;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
#else
    std::filesystem::path helper = current_executable_path();
    std::string parent = std::to_string(static_cast<long long>(getpid()));
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        execl(helper.c_str(), helper.c_str(), "--apply-update", staged.c_str(), target.c_str(), sha256.c_str(), parent.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    return true;
#endif
}

int apply_update_helper(int argc, char** argv) {
    if (argc < 6) return 2;
#if defined(_WIN32)
    return 2;
#else
    std::filesystem::path staged = argv[2];
    std::filesystem::path target = argv[3];
    std::string expected = lower_ascii(argv[4]);
    long long parent = 0;
    try { parent = std::stoll(argv[5]); } catch (...) { return 2; }
    if (parent > 0) {
        for (int i = 0; i < 240; ++i) {
            if (kill(static_cast<pid_t>(parent), 0) != 0 && errno == ESRCH) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }
    std::error_code error;
    auto target_status = std::filesystem::status(target, error);
    auto permissions = target_status.permissions();
    for (int i = 0; i < 40; ++i) {
        std::string actual = sha256_file(staged);
        if (actual.empty() || lower_ascii(actual) != expected) return 3;
        std::filesystem::permissions(staged, permissions, std::filesystem::perm_options::replace, error);
        std::filesystem::path backup = target;
        backup += ".old";
        std::filesystem::remove(backup, error);
        std::filesystem::rename(target, backup, error);
        if (error) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }
        std::filesystem::rename(staged, target, error);
        if (error) {
            std::filesystem::rename(backup, target, error);
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }
        std::filesystem::remove(backup, error);
        pid_t child = fork();
        if (child == 0) {
            execl(target.c_str(), target.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        return child < 0 ? 5 : 0;
    }
    return 6;
#endif
}
