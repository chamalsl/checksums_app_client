#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "token_window.h"
#include "result.h"
#include "task_status.h"
#include "third_party/json_parser/json_parser.h"
#include <gtkmm.h>
#include <thread>
#include <map>
#include <cstdint>
#include <string>
#include <future>
#include <memory>

class TokenWindow;
class MainWindow: public Gtk::Window {

public:
  MainWindow();
  virtual ~MainWindow();
  void setLoginStatus(int status, std::string apiToken);

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
  Gtk::Button m_showAboutBtn;
  Gtk::VBox m_mainContainer;
  TokenWindow* m_loginWindow;
  
private:
  void startVerifying();
  void onFileSelected(int responseId);
  void onResultReceived();
  void displayResult(std::string message, Result::RESULT_TYPE result);
  void enableButtons(bool enable);
  void showAbout();
  std::string m_file_path;
  std::string m_apiToken;
  TaskStatus m_taskStatus;

  Glib::RefPtr<Gdk::Pixbuf> m_correct;
  Glib::RefPtr<Gdk::Pixbuf> m_wrong;
  Glib::RefPtr<Gdk::Pixbuf> m_warning;
  Glib::RefPtr<Gdk::Pixbuf> m_app_icon;
  Glib::RefPtr<Gtk::FileChooserNative> m_file_dialog;
  Glib::Dispatcher m_Dispatcher;
  std::unique_ptr<std::string> m_version;
  std::future<std::unique_ptr<Result>> m_futureResult;
  
};
#endif //MAINWINDOW_H
