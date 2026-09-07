#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <string>

using HttpProgressCallback = std::function<void(std::size_t, std::size_t)>;

struct HttpResponse {
    int status = 0;
    std::string body;
};

HttpResponse http_get(const std::string& url, const std::map<std::string, std::string>& headers = {}, const HttpProgressCallback& progress = {});
HttpResponse http_post_form(const std::string& url, const std::map<std::string, std::string>& fields);
HttpResponse http_post_json(const std::string& url, const std::string& body, const std::map<std::string, std::string>& headers = {});
