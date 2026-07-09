#include "utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <curl/curl.h>
#include <unistd.h>
#include <stdlib.h>
#include <gtkmm.h>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <filesystem>


std::string Utils::calculateSha256Sum(std::string file_path_str){
    std::filesystem::path file_path(file_path_str);
    if (!std::filesystem::exists(file_path)){
      return "";
    }
  
    size_t file_size = std::filesystem::file_size(file_path);
  
    if (file_size == 0){
      return "";
    }
  
    unsigned char *sha_256_hash;
    size_t read_size = 1024;
    char data[read_size];
    std::ifstream file_stream(file_path, std::ios_base::binary);
  
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
    if (evp_ctx == NULL){
      return "";
    }
  
    if (EVP_DigestInit_ex(evp_ctx, EVP_sha256(), NULL) != 1){
      return "";
    }
  
    while (!file_stream.eof()) {
      file_stream.read(data, read_size);
      if (file_stream.gcount()){
        if (EVP_DigestUpdate(evp_ctx, data, file_stream.gcount()) != 1){
          return "";
        }
      }
    }
  
    size_t digest_size = EVP_MD_size(EVP_sha256());
    sha_256_hash = (unsigned char*)OPENSSL_malloc(digest_size);
    if (!sha_256_hash){
      return "";
    }
  
    EVP_DigestFinal_ex(evp_ctx, sha_256_hash, NULL);
    
    return Utils::toHex(sha_256_hash, digest_size);
  }

char Utils::getHexChar(unsigned short number)
{
    std::string hex_chars = "0123456789ABCDEF";
    if (number < 0 || number > 15)
    {
        return '\0';
    }
    return hex_chars[number];
}

std::string Utils::toHex(unsigned char c)
{
    std::string hex("");
    unsigned short num = (unsigned short)c;
    unsigned short remainder = num % 16;
    num = num / 16;
    //std::cout << "Hex" << (unsigned short)c << " :" << remainder << " :" << num << "\n";
    hex += Utils::getHexChar(num);
    hex += Utils::getHexChar(remainder);
    return hex;
}

std::string Utils::toHex(unsigned char *str, size_t length)
{
    std::string hex("");
    for (size_t i=0; i < length; i++) {
       hex.append(Utils::toHex(str[i]));
    }
    return hex;
}

static size_t getResponseFromCurl(void* contents, size_t size, size_t nmemb, void* user_data){
  //std::cout << "Curl write data " << size << " " << nmemb << "\n";
  std::string* data = (std::string*)user_data;
  data->append((char*)contents, size * nmemb);
  return size*nmemb;
}

std::string Utils::requestURL(std::string p_url)
{
  const char* url = p_url.c_str();
  CURL* curl_conn = curl_easy_init();
  curl_easy_setopt(curl_conn, CURLOPT_URL, url);
  curl_easy_setopt(curl_conn, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl_conn, CURLOPT_WRITEFUNCTION, getResponseFromCurl);
  curl_easy_setopt(curl_conn, CURLOPT_TIMEOUT, 10L);
  std::string data;
  curl_easy_setopt(curl_conn, CURLOPT_WRITEDATA, (void *)&data);
  
  int m_status = 0;
  CURLcode code = curl_easy_perform(curl_conn);
  curl_easy_getinfo(curl_conn, CURLINFO_RESPONSE_CODE ,&m_status);
  //std::cout << "Is online " << m_status << " " << code << "\n";
  //std::cout << "Response is " << data << "\n";
  curl_easy_cleanup(curl_conn);
  return data;
}


std::pair<short, std::string> Utils::requestURLWithPost(std::string p_url, std::map<std::string, std::string> p_post_data,
    std::string token, std::map<std::string, std::string> headers)
{
  const char* url = p_url.c_str();

  CURL* curl_conn = curl_easy_init();
  curl_mime *post_data = curl_mime_init(curl_conn);
  for (auto const& val: p_post_data){
    curl_mimepart *part = curl_mime_addpart(post_data);
    curl_mime_name(part, val.first.c_str());
    curl_mime_data(part, val.second.c_str(), CURL_ZERO_TERMINATED);
  }  

  curl_easy_setopt(curl_conn, CURLOPT_URL, url);

  curl_easy_setopt(curl_conn, CURLOPT_MIMEPOST, post_data);
  curl_easy_setopt(curl_conn, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl_conn, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
  curl_easy_setopt(curl_conn, CURLOPT_WRITEFUNCTION, getResponseFromCurl);
  std::string data;
  curl_easy_setopt(curl_conn, CURLOPT_WRITEDATA, (void *)&data);
  struct curl_slist *list = NULL;
  if (!token.empty()){
    std::string auth_header = "Authorization: Bearer ";
    auth_header.append(token);
    list = curl_slist_append(list, auth_header.c_str());
  }

  for (auto const& val: headers){
    std::string header;
    header.append(val.first);
    header.append(":");
    header.append(val.second);
    list = curl_slist_append(list, header.c_str());
  }

  curl_easy_setopt(curl_conn, CURLOPT_HTTPHEADER, list);
  int m_status = 0;
  CURLcode code = curl_easy_perform(curl_conn);
  curl_easy_getinfo(curl_conn, CURLINFO_RESPONSE_CODE ,&m_status);
  //std::cout << "Is online " << m_status << " " << code << "\n";
  //std::cout << "Response is " << data << "\n";
  curl_mime_free(post_data);
  curl_easy_cleanup(curl_conn);
  return std::make_pair(m_status, data);
}


std::unique_ptr<std::string> Utils::getVersion()
{
  Glib::RefPtr< const Glib::Bytes > version = Gio::Resource::lookup_data_global("/data/VERSION");
  if (!version || version->get_size() == 0) {
    return std::make_unique<std::string>("0.0.0");
  }
  else {
    gsize size = version->get_size();
    char* tmp = (char*)malloc(size + 1);
    if (!tmp){
      std::cout << "Out of memory. Could not read version.\n";
      exit(1);
    }

    memcpy(tmp, version->get_data(size), version->get_size());
    tmp[size] = '\0';
    std::unique_ptr<std::string> version = std::make_unique<std::string>(tmp); 
    free(tmp);
    return version;
  }
}

std::string Utils::getDateWithMonthAsText(std::string date_str)
{

  if (date_str.empty()){
    return "";
  }
  
  std::tm tm_struct = {};
  std::istringstream ss(date_str);
  const char* format_input = "%Y-%m-%d";
  const char* format_output = "%Y-%b-%d";
  ss >> std::get_time(&tm_struct, format_input);
  if (ss.fail()) {
      return "";
  }

  std::ostringstream oss;
  oss << std::put_time(&tm_struct, format_output); 

  return oss.str();
}

void Utils::showError(std::string error_msg)
{
    GtkDialogFlags flags = GTK_DIALOG_DESTROY_WITH_PARENT;
    GtkWidget* dialog = gtk_message_dialog_new(NULL, flags, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s",error_msg.c_str());
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

void Utils::showMessage(std::string msg, GtkMessageType p_type)
{
    GtkDialogFlags flags = GTK_DIALOG_DESTROY_WITH_PARENT;
    GtkWidget* dialog = gtk_message_dialog_new(NULL, flags, p_type, GTK_BUTTONS_CLOSE, "%s",msg.c_str());
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}


std::string Utils::trimString(std::string str)
{
  str.erase(0, str.find_first_not_of(" \t\n\r\f\v"));
  str.erase(str.find_last_not_of(" \t\n\r\f\v") + 1);
  return str;
}

bool Utils::isValidEmail(std::string p_email)
{
  if (p_email.empty()) {
    return false;
  }

  size_t at_pos = p_email.find('@');
  if (at_pos == std::string::npos || at_pos == 0 || at_pos == p_email.length() - 1) {
    return false;
  }

  if (p_email.find('@', at_pos + 1) != std::string::npos) {
    return false;
  }

  std::string local_part = p_email.substr(0, at_pos);
  std::string domain_part = p_email.substr(at_pos + 1);

  if (local_part.empty() || domain_part.empty()) {
    return false;
  }

  size_t dot_pos_local_part = local_part.find('.');
  if (dot_pos_local_part == 0 || dot_pos_local_part == local_part.length()-1){
    return false;
  }

  size_t dot_pos_domain_part = domain_part.rfind('.');
  if (dot_pos_domain_part == std::string::npos || dot_pos_domain_part == 0 || dot_pos_domain_part == domain_part.length() - 1) {
    return false;
  }

  if (domain_part.length() - 1 - dot_pos_domain_part < 2) {
      return false; 
  }


  for (char c : local_part) {
    if (!std::isalnum(c) && c != '.' && c != '_' && c != '-' && c != '+') {
      return false;
    }
  }

  for (char c : domain_part) {
    if (!std::isalnum(c) && c != '.' && c != '-') {
      return false;
    }
  }

  return true;
}
