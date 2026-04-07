#pragma once
#include <string>

struct ClientConfig {
    std::string serverUrl   = "coap://deviosfriendlytech.com:5683";
    std::string endpointName = "Navs";
    std::string pskId       = "";
    std::string pskKey      = "";
};

// Global instance, set by main(), read by objects.cpp
extern ClientConfig g_config;
