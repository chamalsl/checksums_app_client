#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <gtkmm.h>
#include "main_window.h"

class MainWindow;
class TokenWindow: public Gtk::Window {

protected:
  Gtk::Label m_tokenLabel;
  Gtk::Entry m_userCode;
  Gtk::Button m_cancelBtn;
  Gtk::Grid m_formGrid;
  Gtk::Box m_buttonBox;

private:
  void cancel();
  MainWindow *m_parent;

  public:
  TokenWindow();
  virtual ~TokenWindow();
  void setParentWindow(MainWindow* parent);
  void showUserCode(std::string p_user_code);
};
#endif //LOGINWINDOW_H