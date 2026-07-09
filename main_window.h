#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "token_window.h"
#include "contactus_window.h"
#include "result.h"
#include "pkce.h"
#include "config.h"
#include "task_status.h"
#include "third_party/json_parser/json_parser.h"
#include <gtkmm.h>
#include <thread>
#include <map>
#include <cstdint>
#include <string>
#include <future>
#include <memory>
#include <libsoup/soup.h>

class TokenWindow;
class MainWindow: public Gtk::Window {

public:
  MainWindow(std::unique_ptr<ChecksumsApp::Config> config);
  virtual ~MainWindow();
  void setLoginStatus(int status, std::string apiToken);
  void requestPkceApiKey();
  void cancelLoginProcess();
  void setConfig(std::unique_ptr<ChecksumsApp::Config> config);

protected:
  void selectFile();
  void handleLoginAndLogout();
  Gtk::Entry m_fileNameText;
  Gtk::Button m_browseBtn;
  Gtk::Button m_checkBtn;
  Gtk::Button m_loginBtn;
  Gtk::Image m_resultImage;
  Gtk::TextView m_resultText;
  Gtk::Box m_addForm;
  Gtk::ProgressBar m_progressBar;
  Gtk::Box m_lowButtonPanel;
  Gtk::AboutDialog m_aboutDialog;
  Gtk::Button m_contactBtn;
  Gtk::Button m_showAboutBtn;
  Gtk::VBox m_mainContainer;
  TokenWindow* m_loginWindow;
  ContacUsWindow* m_contactUsWindow;
  
private:
  void startVerifying();
  void onFileSelected(int responseId);
  void onResultReceived();
  void displayResult(std::string message, Result::RESULT_TYPE result);
  void enableButtons(bool enable);
  void showAbout();
  void showContactUs();
  static void handlePkceChallengeResponse(GObject* source, GAsyncResult* res, gpointer user_data);
  static void handleRequestPkceApiKeyResponse(GObject* source, GAsyncResult* res, gpointer user_data);
  std::string m_file_path;
  std::string m_apiToken;
  TaskStatus m_taskStatus;

  struct {
    std::string code_verifier;
    std::string code_verifier_sha256;
    std::string user_code;
    std::string device_code;
    bool completed = false;

    void reset() {
        code_verifier = "";
        code_verifier_sha256 = "";
        user_code = "";
        device_code = "";
        completed = false;
    }

  } m_pkceData;

  Glib::RefPtr<Gdk::Pixbuf> m_correct;
  Glib::RefPtr<Gdk::Pixbuf> m_wrong;
  Glib::RefPtr<Gdk::Pixbuf> m_warning;
  Glib::RefPtr<Gdk::Pixbuf> m_app_icon;
  Glib::RefPtr<Gtk::FileChooserNative> m_file_dialog;
  Glib::Dispatcher m_Dispatcher;
  std::unique_ptr<std::string> m_version;
  std::unique_ptr<PKCE> m_pkce;
  std::unique_ptr<ChecksumsApp::Config> m_config;
  SoupSession* m_soupSession = NULL;
  std::future<std::unique_ptr<Result>> m_futureResult;
  std::string m_os = "";
  
};
#endif //MAINWINDOW_H
