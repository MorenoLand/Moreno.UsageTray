#pragma once

#include <filesystem>
#include <optional>
#include <string>

struct UpdateInfo {
    std::string version;
    std::string sha256;
    std::string release_url;
    std::string asset_url;
};

std::optional<UpdateInfo> check_for_update();
std::filesystem::path current_executable_path();
std::string sha256_file(const std::filesystem::path& path);
std::filesystem::path download_update(const UpdateInfo& info);
bool launch_update_helper(const std::filesystem::path& staged, const std::filesystem::path& target, const std::string& sha256);
int apply_update_helper(int argc, char** argv);
