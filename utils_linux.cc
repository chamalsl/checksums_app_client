#include "utils.h"
#include <pwd.h>
#include <libsecret/secret.h>

const SecretSchema* UtilsLinux::getSecretStoreSchema()
{
    static const SecretSchema checksum_token_schema = {
      "app.checksums.access_token", SECRET_SCHEMA_NONE,
      {
        {SECRET_STORE_SCHEMA_APPLICATION.c_str(), SECRET_SCHEMA_ATTRIBUTE_STRING}, 
        {SECRET_STORE_SCHEMA_URL.c_str(), SECRET_SCHEMA_ATTRIBUTE_STRING}, 
        {"NULL", SECRET_SCHEMA_ATTRIBUTE_INTEGER},
      }
    };
    return &checksum_token_schema;
}

bool Utils::storeAccessToken(const char* access_token)
{
    GError *error = NULL;
    secret_password_store_sync (Utils::getSecretStoreSchema(), SECRET_COLLECTION_DEFAULT,
                              "checksums.app Access Token", access_token, NULL, &error,
                              SECRET_STORE_SCHEMA_APPLICATION.c_str(), SECRET_STORE_APP_NAME.c_str(),
                              SECRET_STORE_SCHEMA_URL.c_str(), SECRET_STORE_APP_URL.c_str(),
                              NULL);

    if (error != NULL) {
       g_error_free (error);
       return false;
    } else {
       return true;
    }
}

bool Utils::deleteAccessToken()
{
    GError *error = NULL;
    gboolean removed = secret_password_clear_sync (Utils::getSecretStoreSchema(), NULL, &error,
                                              SECRET_STORE_SCHEMA_APPLICATION.c_str(), SECRET_STORE_APP_NAME.c_str(),
                                              SECRET_STORE_SCHEMA_URL.c_str(), SECRET_STORE_APP_URL.c_str(),NULL);

    if (error != NULL) {
        g_error_free (error);
    } 
    return removed;
}

std::string Utils::getAccessToken()
{
    GError *error = NULL;
    gchar *access_token = secret_password_lookup_sync (Utils::getSecretStoreSchema(), NULL, &error,
                                                SECRET_STORE_SCHEMA_APPLICATION.c_str(), SECRET_STORE_APP_NAME.c_str(),
                                                SECRET_STORE_SCHEMA_URL.c_str(), SECRET_STORE_APP_URL.c_str(),NULL);
    std::string access_token_str;

    if (error != NULL) {
        g_error_free (error);
    } 
    
    if (access_token != NULL) {
        access_token_str.append(access_token);
    } 

    return access_token_str;
}

std::string Utils::getHomeDirectory()
{
    std::string home_dir_str("");
    char* home_dir = getenv("HOME");
    if (home_dir == NULL) {
        long buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
        char* buf;
        struct passwd pw;
        struct passwd* result;
        if (buf_size == -1){
            buf_size = 20000;
        }
        buf = (char*)malloc(buf_size);
        if (!buf){
            return std::string();
        }
        int rc = getpwuid_r(getuid(), &pw, buf, buf_size, &result);
        if (result == NULL){
            return std::string();
        }
        
        home_dir_str.append(pw.pw_dir);
        free(buf);
    } else {
        home_dir_str.append(home_dir);
    }
    
    return home_dir_str;
}

std::string Utils::getDataDirectory()
{
    std::string home_dir = Utils::getHomeDirectory();
    if (home_dir.empty()){
        return std::string();
    }

    std::filesystem::path home_dir_path(home_dir);
    home_dir_path.append(".local/share/rammini.com/checksums");
    return home_dir_path.u8string();
}