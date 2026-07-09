#include "config.h"
#include "utils.h"
#include <iostream>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

ChecksumsApp::Config::Config()
{
    m_config_file_path = fs::path(Utils::getDataDirectory()) / "checksums-app.conf";
    //std::cout << "Data Directory " << m_config_file_path.string() << "\n";
}

bool ChecksumsApp::Config::initialize()
{
    if (!fs::exists(m_config_file_path)) {
        bool created = createConfigFile();
        if (!created) {
            return false;
        }
    }

    std::ifstream file(m_config_file_path);
    if (!file.is_open()){
        std::cout << "Could not open configuraation file " << m_config_file_path.string() << "\n";
        return false;
    }

    std::string line;
    while(std::getline(file, line)){

        line = Utils::trimString(line);
        if (line.empty()){
            continue;
        }

        if (line.at(0) == '#'){
            continue;
        }

        size_t equal_pos = line.find('=');
        if (equal_pos == std::string::npos || equal_pos == 0 || equal_pos == line.length()-1){
            std::cout << "Invalid configuration file \n";
            return false;
        }
        std::string key = Utils::trimString(line.substr(0,equal_pos));
        std::string value = Utils::trimString(line.substr(equal_pos + 1));
        configData[key] = value;
    }

    if (configData.size()) {
        return true;
    } else {
        std::cout << "Configuration file is empty \n";
        return false;
    }
    
}

std::string ChecksumsApp::Config::getValue(std::string key)
{
    if (configData.find(key) != configData.end()) {
        return configData[key];
    }
    return "";
}

void ChecksumsApp::Config::setValue(std::string key, std::string value)
{
    configData[key] = value;
    saveConfigFile();
}

bool ChecksumsApp::Config::getLoggedIn()
{
    std::string value = getValue(ChecksumsApp::LOGGED_IN);

    if (value.empty()) {
        return false;
    }

    try {
        int num = std::stoi(value);
        if (num == 1) {
            return true;
        } else {
            return false;
        }
    } catch (const std::invalid_argument& e) {
        return false;
    } catch (const std::out_of_range& e) {
        return false;
    }
}

bool ChecksumsApp::Config::saveConfigFile()
{
    std::ofstream file(m_config_file_path, std::ios::out|std::ios::trunc);

    if (!file.is_open()){
        std::cout << "Could not open configuraation file " << m_config_file_path.string() << "\n";
        return false;
    }

    for (const auto& [key, value] : configData) {
        file << key << "=" << value << std::endl;
    }
    return false;
}

bool ChecksumsApp::Config::createConfigFile()
{
    fs::path parent_folders = m_config_file_path.parent_path();
    bool created = fs::create_directories(parent_folders);

    if (!created) {
        std::cout << "Could not create parent directories for configuration file\n";
        return false;
    }

    std::ofstream file(m_config_file_path, std::ios::out);
    if (!file.is_open()){
        std::cout << "Could not create configuration file " << m_config_file_path.string() << "\n";
        return false;
    }

    file << ChecksumsApp::LOGGED_IN << "=" << "0" << std::endl;
    file.close();
    return true;
}
