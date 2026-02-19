#include <string>

static const std::string URL_GET_DEVICE_CODE = "http://127.0.0.1:8000/pkce/challenge";

class PKCE {

    public:
        std::string  getCodeVerifier();
        std::string  getCodeVerifierSha256(std::string p_code_verifier);

};