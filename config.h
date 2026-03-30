#include <string>
#include <map>
#include <filesystem>

#ifndef CONFIG_H
#define CONFIG_H

namespace fs = std::filesystem;

namespace ChecksumsApp{
    #ifdef LOCAL_DEV
    inline constexpr char const* URL_PKCE_REQUEST_API_KEY = "http://127.0.0.1:8000/pkce/requestApiKey";
    inline constexpr char const* URL_PKCE_REQUEST_DEVICE_AUTHORIZATION = "http://127.0.0.1:8000/pkce/request_device_authorization?device_code=";
    inline constexpr char const* URL_PKCE_CHALLENGE = "http://127.0.0.1:8000/pkce/challenge";

    inline constexpr char const* URL_API_FIND_BY_NAME = "http://127.0.0.1:8000/api/findByFileName";
    inline constexpr char const* URL_API_FIND_BY_NAME_AUTH = "http://127.0.0.1:8000/api/findByFileNamePrivate";
    inline constexpr char const* URL_API_FIND_BY_CHECKSUMS = "http://127.0.0.1:8000/api/findByChecksums";
    inline constexpr char const* URL_API_FIND_BY_CHECKSUMS_AUTH = "http://127.0.0.1:8000/api/findByChecksumsPrivate";
    #else
    inline constexpr char const* URL_PKCE_REQUEST_API_KEY = "https://checksums.app/pkce/requestApiKey";
    inline constexpr char const* URL_PKCE_REQUEST_DEVICE_AUTHORIZATION = "https://checksums.app/pkce/request_device_authorization?device_code=";
    inline constexpr char const* URL_PKCE_CHALLENGE = "https://checksums.app/pkce/challenge";

    inline constexpr char const* URL_API_FIND_BY_NAME = "https://checksums.app/api/findByFileName";
    inline constexpr char const* URL_API_FIND_BY_NAME_AUTH = "https://checksums.app/api/findByFileNamePrivate";
    inline constexpr char const* URL_API_FIND_BY_CHECKSUMS = "https://checksums.app/api/findByChecksums";
    inline constexpr char const* URL_API_FIND_BY_CHECKSUMS_AUTH = "https://checksums.app/api/findByChecksumsPrivate";
    #endif

    inline constexpr char const* LOGGED_IN = "logged-in";

class Config {

    public:
        Config();
        bool initialize();
        std::string  getValue(std::string key);
        void setValue(std::string key, std::string value);
        bool getLoggedIn();
        bool saveConfigFile();

    private:
        std::map<std::string, std::string> configData;
        fs::path m_config_file_path;
        
        bool createConfigFile();
};

}
#endif //CONFIG_H

