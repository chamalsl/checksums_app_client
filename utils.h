#include <string>
#include <memory>
#include <map>


static const std::string SECRET_STORE_SCHEMA_APPLICATION = "Application";
static const std::string SECRET_STORE_SCHEMA_URL = "URL";
static const std::string SECRET_STORE_TOKEN_NAME = "app.checksums Access Token";
static const std::string SECRET_STORE_APP_NAME = "Checksums";
static const std::string SECRET_STORE_APP_URL = "https://checksums.app/";
static const std::string SECRET_STORE_TOKEN_NAME_WINDOWS = "app.checksums Access Token";

class Utils{

  public:
  static std::string calculateSha256Sum(std::string file_path_str);
  static char getHexChar(unsigned short number);
  static std::string toHex(unsigned char c);
  static std::string toHex(unsigned char* str, size_t length);
  static std::string requestURL(std::string url);
  static std::pair<short, std::string> requestURLWithPost(std::string p_url, std::map<std::string, std::string> p_post_data, 
      std::string token, std::map<std::string, std::string> headers);

  static std::string getHomeDirectory();
  static std::string getDataDirectory();
  static std::unique_ptr<std::string> getVersion();
  static bool storeAccessToken(const char* access_token);
  static bool deleteAccessToken();
  static std::string getAccessToken();
  static void showError(std::string error_msg);

};