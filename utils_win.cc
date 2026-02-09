#include "utils.h"
#include "windows.h"
#include "wincred.h"

bool Utils::storeAccessToken(const char* access_token)
{
    CREDENTIALA cred = {0};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = strdup(SECRET_STORE_TOKEN_NAME_WINDOWS.c_str());
    cred.CredentialBlobSize = strlen(access_token);
    cred.CredentialBlob = (LPBYTE) access_token;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    if (!CredWriteA(&cred, 0)) {
        return false;
    }

    return true;
}

bool Utils::deleteAccessToken()
{
    char* key_name = strdup(SECRET_STORE_TOKEN_NAME_WINDOWS.c_str());

    if (!CredDeleteA(key_name, CRED_TYPE_GENERIC, 0)) {
        return false;
    }
    return true;
}

std::string Utils::getAccessToken()
{
    std::string access_token_str;
    PCREDENTIALA cred ;

    char* key_name = strdup(SECRET_STORE_TOKEN_NAME_WINDOWS.c_str());
    if (CredReadA(key_name, CRED_TYPE_GENERIC, 0, &cred)) {
         access_token_str.assign((char*)cred->CredentialBlob, cred->CredentialBlobSize);
         CredFree(cred);
    }

    return access_token_str;
}

std::string Utils::getHomeDirectory()
{
    return "";
}

std::string Utils::getDataDirectory()
{
    return "";
}