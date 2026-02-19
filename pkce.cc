#include "pkce.h"
#include "utils.h"
#include "third_party/json_parser/json_parser.h"
#include <vector>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>

std::string PKCE::getCodeVerifier()
{
    std::vector<unsigned char> rand_data(96);

    if (!RAND_bytes(rand_data.data(), rand_data.size())){
        throw std::runtime_error("Could not generate random bytes!");
    }

    size_t base64_len = 4 * ((rand_data.size()+2)/3);
    std::string base64(base64_len, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&base64[0]),rand_data.data(),rand_data.size());

    for (char &c : base64) {
        if (c == '+'){
            c = '-';
        } else if (c == '/'){
            c = '_';
        }
    }
    base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());
    return base64;
}

std::string PKCE::getCodeVerifierSha256(std::string p_code_verifier)
{
    EVP_MD_CTX *evp_ctx_256 = EVP_MD_CTX_new();
    if (evp_ctx_256 == NULL) {
        throw std::runtime_error("Could not create openssl context!");
    }

    if (EVP_DigestInit_ex(evp_ctx_256, EVP_sha256(), NULL) != 1){
        throw std::runtime_error("Could not initialize openssl context!");
    }

    if (EVP_DigestUpdate(evp_ctx_256, p_code_verifier.c_str(), p_code_verifier.length()) != 1 ){
        throw std::runtime_error("Could not create sha256 digest!");
    }

    size_t digest_size = EVP_MD_size(EVP_sha256());
    unsigned char* sha_256_hash = (unsigned char*)OPENSSL_malloc(digest_size);
    if (!sha_256_hash){
        throw std::runtime_error("Could not allocate memory for sha256 digest!");
    }
    EVP_DigestFinal_ex(evp_ctx_256, sha_256_hash, NULL);
    std::string local_sha256 = Utils::toHex(sha_256_hash, digest_size);

    OPENSSL_free(sha_256_hash);
    EVP_MD_CTX_free(evp_ctx_256);

    return local_sha256;
}

