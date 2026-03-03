#include "api.h"
#include "config.h"
#include "utils.h"
#include <string>
#include <algorithm>
#include <map>
#include <glibmm/markup.h>

std::pair<short, std::string>  Api::findByFileName(std::string file_name, std::string apiToken)
{
  std::string url = ChecksumsApp::URL_API_FIND_BY_NAME;
  if (!apiToken.empty()){
    url = ChecksumsApp::URL_API_FIND_BY_NAME_AUTH;
  }

  std::map<std::string, std::string> post_data;
  post_data["filename"] = file_name;
  std::map<std::string, std::string> headers;
  headers["Accept"] = "application/json";
  return Utils::requestURLWithPost(url, post_data, apiToken, headers);
}

std::pair<short, std::string>  Api::findByChecksums(std::string sha256, std::string sha512, std::string apiToken)
{
    std::string url = ChecksumsApp::URL_API_FIND_BY_CHECKSUMS;
    if (!apiToken.empty()){
      url = ChecksumsApp::URL_API_FIND_BY_CHECKSUMS_AUTH;
    }

    std::map<std::string, std::string> post_data;
    post_data["sha256"] = sha256;
    post_data["sha512"] = sha512;
    std::map<std::string, std::string> headers;
    headers["Accept"] = "application/json";
    return Utils::requestURLWithPost(url, post_data, apiToken, headers);
}

std::string Api::getResultToDisplay(JsonObject *file_json, std::string local_file_sha256, std::string local_file_sha512,
                                    Result::RESULT_TYPE &result_type)
{
  bool matched = false;
  std::string result;
  JsonObject* remote_sha256_json = JsonParser::findByPropertyName(file_json, "sha256sum");
  JsonObject* remote_sha512_json = JsonParser::findByPropertyName(file_json, "sha512sum");
  JsonObject* software_name_json = JsonParser::findByPropertyName(file_json, "software_name");
  JsonObject* version_json = JsonParser::findByPropertyName(file_json, "version");
  JsonObject* release_date_json = JsonParser::findByPropertyName(file_json, "release_date");
  JsonObject* file_name_json = JsonParser::findByPropertyName(file_json, "file_name");
  JsonObject* public_json = JsonParser::findByPropertyName(file_json, "public");
  if (!remote_sha256_json || !remote_sha512_json || !public_json || !file_name_json){
    return "";
  }

  if (public_json->integerValue == 1 && !software_name_json){
    return "";
  }

  std::string remote_sha256sum = remote_sha256_json->stringValue;
  std::string remote_sha512sum = remote_sha512_json->stringValue;
  
  std::transform(remote_sha256sum.begin(), remote_sha256sum.end(), remote_sha256sum.begin(), static_cast<int(*)(int)>(std::tolower));
  std::transform(remote_sha512sum.begin(), remote_sha512sum.end(), remote_sha512sum.begin(), static_cast<int(*)(int)>(std::tolower));

  result.append("File name: ");
  result.append(Glib::Markup::escape_text(file_name_json->stringValue));
  if (public_json->integerValue == 0) {
    result.append("\n(Personal file)");
  }
  result.append("\n");

  if (local_file_sha512 == remote_sha512sum){
    matched = true;
    result.append("\nSha512 matched!");
  }
  
  if (local_file_sha256 == remote_sha256sum){
    matched = true;
    result.append("\nSha256 matched!");
  }
  if (!matched) {
    result.append("\nChecksums <b>DID NOT</b> match!");
    result_type = Result::RESULT_TYPE::WRONG;
  }else{
    result_type = Result::RESULT_TYPE::CORRECT;
  }

  result.append("\n\n<b><u>Checksums of selected file</u></b>");

  result.append("\n\nSha 256 : ");
  result.append(local_file_sha256);

  result.append("\n\nSha 512 : ");
  result.append(local_file_sha512);

  if (!matched) {
    result.append("\n\n<b><u>Checksums in our Database</u></b>");
    if (!remote_sha256sum.empty()){
      result.append("\n\nSha 256 : ");
      result.append(Glib::Markup::escape_text(remote_sha256sum));
    }

    if (!remote_sha512sum.empty()){
      result.append("\n\nSha 512 : ");
      result.append(Glib::Markup::escape_text(remote_sha512sum));
    }
  }
  
  if (public_json->integerValue == 1) {
    result.append("\n\nSoftware: ");
    result.append(Glib::Markup::escape_text(software_name_json->stringValue));
    result.append("\nVersion: ");
    if (version_json){
      result.append(Glib::Markup::escape_text(version_json->stringValue));
    }     
    result.append("\nRelease date: ");
    result.append(Utils::getDateWithMonthAsText(Glib::Markup::escape_text(release_date_json->stringValue)));
  }

  std::string not_available_str;
  if (remote_sha256sum.empty()){
    not_available_str.append("\nsha 256");
  }

   if(remote_sha512sum.empty()){
    not_available_str.append("\nsha 512");
  }

  if (!not_available_str.empty()){
    result.append("\n\n<b>* <i>These checksums were not available in our database.</i></b>");
    result.append(not_available_str);
  }

  return result;
}