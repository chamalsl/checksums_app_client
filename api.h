#ifndef API_H
#define API_H

#include <string>
#include "result.h"
#include "third_party/json_parser/json_parser.h"


class Api{

    public:
        static std::pair<short, std::string> sendContactUsMessage(std::string fname, std::string email, std::string subject, std::string body);
        static std::pair<short, std::string> findByFileName(std::string file_name, std::string apiToken);
        static std::pair<short, std::string>  findByChecksums(std::string sha256, std::string sha512, std::string apiToken);
        static std::string getResultToDisplay(JsonObject *file_json, std::string local_file_sha256, std::string local_file_sha512, Result::RESULT_TYPE &result_type);
};

#endif //API_H