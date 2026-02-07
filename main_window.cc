#include "main_window.h"
#include "utils.h"
#include "api.h"
#include "result.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <future>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <giomm/resource.h>

MainWindow::MainWindow()
:m_mainContainer(Gtk::Orientation::ORIENTATION_VERTICAL, 5),
 m_addForm(Gtk::Orientation::ORIENTATION_HORIZONTAL, 5),
 m_lowButtonPanel(Gtk::Orientation::ORIENTATION_HORIZONTAL, 5),
 m_browseBtn("Browse"),
 m_checkBtn("Check"),
 m_loginBtn("Login"),
 m_showAboutBtn(),
 m_resultImage()
{
  set_position(Gtk::WIN_POS_CENTER);
  set_title("Checksums");
  set_default_size(660,400);
  auto css_provider = Gtk::CssProvider::create();
  css_provider->load_from_resource("/css/shasums.css");
  Gtk::StyleContext::add_provider_for_screen(Gdk::Screen::get_default(),css_provider, GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
  m_resultText.set_name("result_text");
  m_correct = Gdk::Pixbuf::create_from_resource("/images/correct.svg");
  m_wrong = Gdk::Pixbuf::create_from_resource("/images/wrong.svg");
  m_warning = Gdk::Pixbuf::create_from_resource("/images/warning.svg");
  m_app_icon = Gdk::Pixbuf::create_from_resource("/images/app.checksums.svg");
  set_icon(m_app_icon);

  m_version = Utils::getVersion();
  m_aboutDialog.set_transient_for(*this);
  m_aboutDialog.set_logo(Gdk::Pixbuf::create_from_resource("/images/coconut.png"));
  m_aboutDialog.set_version(*m_version.get());
  m_aboutDialog.set_program_name("CheckSums");
  m_aboutDialog.set_copyright("checksums.app");
  m_aboutDialog.set_license_type(Gtk::License::LICENSE_MIT_X11);
  std::vector<Glib::ustring> list_authors;
  list_authors.push_back("Chamal De Silva");
  list_authors.push_back("Thanks to these open source software-");
  list_authors.push_back("libgtkmm");
  list_authors.push_back("openssl");
  list_authors.push_back("libcurl");
  list_authors.push_back("libsecret");
  m_aboutDialog.set_authors(list_authors);



  m_mainContainer.set_homogeneous(false);
  m_fileNameText.set_width_chars(40);
  m_fileNameText.set_editable(false);
  m_addForm.pack_start(m_fileNameText, false, false, 5);
  //m_browseBtn.set_sensitive(false);
  //m_checkBtn.set_sensitive(false);
  m_addForm.add(m_browseBtn);
  m_addForm.add(m_checkBtn);
  m_addForm.add(m_resultImage);
  m_addForm.add(m_loginBtn);
  m_mainContainer.pack_start(m_addForm, false, false, 5);
  m_addForm.set_valign(Gtk::ALIGN_BASELINE);
  m_mainContainer.set_valign(Gtk::ALIGN_FILL);
  m_mainContainer.pack_start(m_resultText, true, true, 5);
  m_showAboutBtn.set_image_from_icon_name("help-about");
  m_progressBar.set_show_text(true);
  m_progressBar.set_halign(Gtk::Align::ALIGN_CENTER);
  m_progressBar.set_valign(Gtk::Align::ALIGN_CENTER);
  m_lowButtonPanel.pack_start(m_progressBar, false, false, 5);
  m_lowButtonPanel.pack_end(m_showAboutBtn, false, false, 5);
  m_mainContainer.pack_end(m_lowButtonPanel, false, false, 5);
  add(m_mainContainer);
  m_progressBar.set_no_show_all(true);
  m_progressBar.set_visible(false);

  m_showAboutBtn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::showAbout));
  m_browseBtn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::selectFile));
  m_checkBtn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::startVerifying));
  m_loginBtn.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::handleLoginAndLogout));
  m_loginWindow = new TokenWindow();
  m_loginWindow->setParentWindow(this);
  m_loginWindow->set_default_size(100,200);
  m_loginWindow->set_modal(true);
  m_loginWindow->set_transient_for(*this);
  m_loginWindow->set_position(Gtk::WIN_POS_CENTER_ON_PARENT);

  m_file_dialog = Gtk::FileChooserNative::create("Select File", *this, Gtk::FILE_CHOOSER_ACTION_OPEN, "Select", "Cancel");
  m_file_dialog->set_transient_for(*this);
  m_file_dialog->set_modal(true);
  m_file_dialog->signal_response().connect(sigc::mem_fun(*this, &MainWindow::onFileSelected));

  m_apiToken = Utils::getAccessToken();
  if (!m_apiToken.empty()){
    m_loginBtn.set_label("Logout");
  }

  m_resultText.set_wrap_mode(Gtk::WrapMode::WRAP_CHAR);
  m_resultText.set_left_margin(15);
  m_resultText.set_editable(false);
  show_all_children();
  m_Dispatcher.connect(sigc::mem_fun(*this, &MainWindow::onResultReceived));
}

void MainWindow::selectFile(){
  //std::cout << "Opening File Chooser\n";
  
  //file_dialog.set_transient_for(*this);
  //file_dialog.add_button("Cancel", Gtk::RESPONSE_CANCEL);
  //file_dialog.add_button("Select", Gtk::RESPONSE_OK);

  //int result = file_dialog.run();
  m_file_dialog->show();
}

std::unique_ptr<Result> verifyFile(Glib::Dispatcher* p_dispatcher, std::string file_path_str, 
  std::string apiToken, TaskStatus* task_status){
    
  #define COMPLETED \
    task_status->percentage = 100; \
    p_dispatcher->emit(); \
    return result; \

  #define HANDLE_ERROR \
    task_status->error = true; \
    p_dispatcher->emit(); \
    return result; \

  std::unique_ptr<Result> result = std::make_unique<Result>();
  std::filesystem::path file_path(file_path_str);
  if (!std::filesystem::exists(file_path)){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "File does not exist!";
    HANDLE_ERROR;
  }

  size_t file_size = std::filesystem::file_size(file_path);

  if (file_size == 0){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "File is empty!";
    HANDLE_ERROR
  }

  unsigned char *sha_256_hash;
  unsigned char *sha_512_hash;
  size_t read_count = 0;
  size_t read_size = 1048576;
  size_t hundred_mb = 104857600;
  if (file_size > hundred_mb){
    read_size = hundred_mb;
  }
  char* data = (char*)malloc(read_size);

  if (!data){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "Could not allocate memory.!";
    HANDLE_ERROR;
  }
  std::ifstream file_stream(file_path, std::ios_base::binary);

  EVP_MD_CTX *evp_ctx_256 = EVP_MD_CTX_new();
  EVP_MD_CTX *evp_ctx_512 = EVP_MD_CTX_new();
  
  if (evp_ctx_256 == NULL || evp_ctx_512 == NULL){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "Error occurred while calculating checksums.!";
    p_dispatcher->emit();
    return result;
  }

  if (EVP_DigestInit_ex(evp_ctx_256, EVP_sha256(), NULL) != 1){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "Error occurred while calculating sha 256.!";
    HANDLE_ERROR;
  }

  if (EVP_DigestInit_ex(evp_ctx_512, EVP_sha512(), NULL) != 1){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "Error occurred while calculating sha 512.!";
    HANDLE_ERROR;
  }
  
  while (!file_stream.eof()) {
    file_stream.read(data, read_size);
    if (file_stream.gcount()){
      if (EVP_DigestUpdate(evp_ctx_256, data, file_stream.gcount()) != 1  
          || EVP_DigestUpdate(evp_ctx_512, data, file_stream.gcount()) != 1 ){
        result->m_resultType = Result::RESULT_TYPE::WRONG;
        result->m_message = "Error occurred while calculating checksums.!";
        HANDLE_ERROR;
      }else {
        read_count = read_count + file_stream.gcount();
        task_status->percentage = (((double)read_count/file_size) * 90);
        p_dispatcher->emit();
      }
    }
  }

  file_stream.close();

  size_t digest_size = EVP_MD_size(EVP_sha256());
  sha_256_hash = (unsigned char*)OPENSSL_malloc(digest_size);
  if (!sha_256_hash){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "Could not allocate memory.!";
    HANDLE_ERROR;
  }
  EVP_DigestFinal_ex(evp_ctx_256, sha_256_hash, NULL);
  std::string local_sha256 = Utils::toHex(sha_256_hash, digest_size);

  digest_size = EVP_MD_size(EVP_sha512());
  sha_512_hash = (unsigned char*)OPENSSL_malloc(digest_size);
  if (!sha_512_hash){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    result->m_message = "Could not allocate memory.!";
    HANDLE_ERROR;
  }
  EVP_DigestFinal_ex(evp_ctx_512, sha_512_hash, NULL);
  std::string local_sha512 = Utils::toHex(sha_512_hash, digest_size);
  
  OPENSSL_free(sha_256_hash);
  OPENSSL_free(sha_512_hash);
  EVP_MD_CTX_free(evp_ctx_256);
  EVP_MD_CTX_free(evp_ctx_512);
  free(data);

  task_status->percentage = 95;
  p_dispatcher->emit();

  std::transform(local_sha256.begin(), local_sha256.end(), local_sha256.begin(), static_cast<int(*)(int)>(std::tolower));
  std::transform(local_sha512.begin(), local_sha512.end(), local_sha512.begin(), static_cast<int(*)(int)>(std::tolower));
  std::string file_name = std::filesystem::path(file_path).filename().string();

  std::pair<short, std::string> response = Api::findByChecksums(local_sha256, local_sha512, apiToken);
  result->m_httpStatus = response.first;
  result->m_message = response.second;
  
  if (result->m_httpStatus == 401){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    COMPLETED;
  }

  if (result->m_httpStatus != 200 || result->m_message.empty()){
    result->m_message = "Network or system error!";
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    COMPLETED;
  }

  JsonParser json_parser;
  std::unique_ptr<JsonObject> json_obj = json_parser.parseJson(result->m_message);

  if (json_obj->type == JsonType::OBJECT && json_obj->arrayItems.size() > 1){
    Result::RESULT_TYPE result_type;
    result->m_message = Api::getResultToDisplay(json_obj.get(), local_sha256, local_sha512, result_type);
    result->m_resultType = result_type;
    COMPLETED;
  }

  task_status->percentage = 98;
  p_dispatcher->emit();


  response = Api::findByFileName(file_name, apiToken);
  result->m_httpStatus = response.first;
  result->m_message = response.second;

  if (result->m_httpStatus == 401){
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    COMPLETED;
  }

  if (result->m_httpStatus != 200 || result->m_message.empty()){
    result->m_message = "Network or system error!";
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    COMPLETED;
  }

  json_obj = json_parser.parseJson(result->m_message);

  std::string result_message;
  if (json_obj->arrayItems.size() == 0){
    result_message.append("Our database does not have any files with same checksum or filename.");
    result_message.append("\n\nSha 256 :\n");
    result_message.append(local_sha256);
    result_message.append("\n\nSha 512 :\n");
    result_message.append(local_sha512);
    result->m_resultType = Result::RESULT_TYPE::WARNING;
    result->m_message = result_message;
    COMPLETED;
  }
  else if (json_obj->arrayItems.size() > 1){
    result_message.append("Our database has multiple files with same name.");
    result_message.append("\nBut none of them have same sha 256 or sha512!");
    result_message.append("\n\nSha 256 :\n");
    result_message.append(local_sha256);
    result_message.append("\n\nSha 512 :\n");
    result_message.append(local_sha512);
    result->m_resultType = Result::RESULT_TYPE::WARNING;
    result->m_message = result_message;
    COMPLETED;
  }
  else if (json_obj->arrayItems.size() == 1){
    Result::RESULT_TYPE result_type;
    JsonObject* file_json = json_obj->arrayItems.at(0).get();
    result->m_message = Api::getResultToDisplay(file_json, local_sha256, local_sha512, result_type);
    result->m_resultType = Result::RESULT_TYPE::WRONG;
    COMPLETED;
  }

  result->m_message = "Unknown Error!";
  result->m_resultType = Result::RESULT_TYPE::WRONG;
  COMPLETED;
}

void MainWindow::onResultReceived()
{
  if (m_futureResult.valid()){
    if (m_taskStatus.percentage == 100 || m_taskStatus.error == true) {
      m_futureResult.wait();
      std::unique_ptr<Result> result = m_futureResult.get();
      enableButtons(true);
      if (result->m_httpStatus == 401){
        Utils::showError("Your access token is invalid or expired.\n"
                        "Please click Check button again to verify a public file.\n"
                        "Please request and enter a new token to verify a personal file.\n"
                        );
        handleLoginAndLogout();
        return;
      }

      displayResult(result->m_message, result->m_resultType);
      m_progressBar.set_fraction((float)m_taskStatus.percentage/100);
    }else{
      m_progressBar.set_fraction((float)m_taskStatus.percentage/100);
    }
  }
}

void MainWindow::startVerifying(){
  if (m_file_path.empty()){
    Utils::showError("Please click Browse button to select a file.");
    return;
  }

  m_progressBar.set_no_show_all(false);
  m_progressBar.set_visible(true);
  m_taskStatus.error = false;
  m_taskStatus.percentage = 0;
  m_progressBar.set_fraction(0);
  enableButtons(false);
  m_futureResult = std::async(std::launch::async,verifyFile, &m_Dispatcher, m_file_path, m_apiToken, &m_taskStatus);
}

void MainWindow::onFileSelected(int response_id)
{
  switch (response_id){
    case Gtk::ResponseType::RESPONSE_ACCEPT:{
      m_file_path = m_file_dialog->get_file()->get_path();
      m_fileNameText.set_text(m_file_path);
      displayResult("",Result::RESULT_TYPE::EMPTY);
      break;
    }
    case Gtk::ResponseType::RESPONSE_CANCEL:{
      break;
    }
    default:{
      break;
    }
  }

}

void MainWindow::handleLoginAndLogout()
{
  if (m_apiToken.empty()) {
    m_loginWindow->set_visible(true);
  }else {
    bool status = Utils::deleteAccessToken();
    if (!status){
      Utils::showError("Could not delete access token.");
    }else{
      m_loginBtn.set_label("Login");
      m_apiToken.clear();
    }   
  }
}


void MainWindow::displayResult(std::string message, Result::RESULT_TYPE result_type)
{
  m_resultText.get_buffer().get()->set_text(message);
  if (result_type == Result::RESULT_TYPE::CORRECT) {
    m_resultImage.set(m_correct);
  }
  else if (result_type == Result::RESULT_TYPE::WRONG) {
    m_resultImage.set(m_wrong);
  }
  else if (result_type == Result::RESULT_TYPE::WARNING) {
    m_resultImage.set(m_warning);
  }
  else{
    m_resultImage.clear();
  }
}

void MainWindow::enableButtons(bool enable)
{
  m_checkBtn.set_sensitive(enable);
  m_browseBtn.set_sensitive(enable);
  m_loginBtn.set_sensitive(enable);
}

void MainWindow::showAbout()
{
  m_aboutDialog.present();
}


MainWindow::~MainWindow(){
  delete m_loginWindow;
}

void MainWindow::setLoginStatus(int status, std::string apiToken)
{
  if (status == 1){
    m_apiToken = apiToken;
    /*m_browseBtn.set_sensitive(true);
    m_checkBtn.set_sensitive(true);*/
    m_loginBtn.set_label("Logout");
  }
}
