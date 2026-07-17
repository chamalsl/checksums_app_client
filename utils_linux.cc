#include "utils.h"
#include <pwd.h>
#include <libsecret/secret.h>
#include <filesystem>
#include <iostream>

const static SecretSchema* getSecretStoreSchema()
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
    secret_password_store_sync (getSecretStoreSchema(), SECRET_COLLECTION_DEFAULT,
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
    gboolean removed = secret_password_clear_sync (getSecretStoreSchema(), NULL, &error,
                                              SECRET_STORE_SCHEMA_APPLICATION.c_str(), SECRET_STORE_APP_NAME.c_str(),
                                              SECRET_STORE_SCHEMA_URL.c_str(), SECRET_STORE_APP_URL.c_str(),NULL);

    if (error != NULL) {
        g_error_free (error);
    } 
    return removed;
}


std::string Utils::getAccessToken(){

    GError *error = NULL;
    gchar *access_token = secret_password_lookup_sync (getSecretStoreSchema(), NULL, &error,
                                                SECRET_STORE_SCHEMA_APPLICATION.c_str(), SECRET_STORE_APP_NAME.c_str(),
                                                SECRET_STORE_SCHEMA_URL.c_str(), SECRET_STORE_APP_URL.c_str(),NULL);
    std::string access_token_str = "";

    if (error != NULL) {
        g_error_free (error);
    } 

    if (access_token != NULL) {
        access_token_str.append(access_token);
    } 

    return access_token_str;
}



/*
  Unlocks default secret collection if it is locked.
*/
bool Utils::unlockSecretServiceDefaultCollection()
{
    GError *error = nullptr;

    /*
    If application is running inside snap sandbox, then application cannot unlock system's default collection.
    It is also not necessary, when application is running as snap.
    */
    if (std::getenv("SNAP")){
        return true;
    }

    // 1. Get the Secret Service instance
    SecretService *service = secret_service_get_sync(SECRET_SERVICE_NONE, nullptr, &error);
    if (error != nullptr) {
        std::cerr << "Error getting secret service: " << error->message << std::endl;
        g_error_free(error);
        return false;
    }

    // 2. Get the default collection (the 'login' keyring)
    SecretCollection *collection = secret_collection_for_alias_sync(
        service, SECRET_COLLECTION_DEFAULT, SECRET_COLLECTION_NONE, nullptr, &error
    );

    if (error != nullptr) {
        std::cerr << "Error finding default collection: " << error->message << std::endl;
        g_object_unref(service);
        g_error_free(error);
        return false;
    }

    if (collection != nullptr) {
        
        if (!secret_collection_get_locked(collection)) {
            return true;
        }

        GList *collections = g_list_append(nullptr, collection);

        // 3. Unlock the collection (prompts the user for their password)
        GList *unlocked = nullptr;
        secret_service_unlock_sync(service, collections, nullptr, &unlocked, &error);

        if (error != nullptr) {
            std::cerr << "Failed to unlock keyring: " << error->message << std::endl;
            g_error_free(error);
            return false;
        }          
        g_list_free_full(unlocked, g_object_unref);

        g_list_free(collections);
        g_object_unref(collection);
    }

    g_object_unref(service);
    return true;
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