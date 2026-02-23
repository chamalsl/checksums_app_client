#include "token_window.h"
#include "utils.h"
#include "third_party/json_parser/json_parser.h"
#include <iostream>
#include "api.h"


TokenWindow::TokenWindow() : m_tokenLabel("Token"),
                             m_doneBtn("Done"),
                             m_cancelBtn("Cancel"),
                             m_boxLayout(Gtk::Orientation::ORIENTATION_VERTICAL),
                             m_buttonsLayout(Gtk::Orientation::ORIENTATION_HORIZONTAL)
{
  set_title("Security Code");
  
  m_boxLayout.set_orientation(Gtk::ORIENTATION_VERTICAL);
  m_boxLayout.set_spacing(10);

  m_tokenLabel.set_line_wrap(true);
  m_tokenLabel.set_justify(Gtk::JUSTIFY_CENTER);
  m_tokenLabel.set_halign(Gtk::ALIGN_CENTER);
  m_tokenLabel.set_max_width_chars(30);
  m_tokenLabel.set_text("Enter this security code in https://checksums.app to verify your device.!");
  m_tokenLabel.set_halign(Gtk::ALIGN_CENTER);
  m_userCode.set_editable(false); 
  m_userCode.set_name("Security Code");
  m_userCode.set_width_chars(10);
  m_userCode.set_halign(Gtk::ALIGN_CENTER);

  m_cancelBtn.set_halign(Gtk::ALIGN_CENTER);
  m_cancelBtn.set_margin_bottom(10);
  m_doneBtn.set_halign(Gtk::ALIGN_CENTER);
  m_doneBtn.set_margin_bottom(10);
  m_buttonsLayout.pack_start(m_cancelBtn);
  m_buttonsLayout.pack_start(m_doneBtn);

  m_boxLayout.pack_start(m_tokenLabel);
  m_boxLayout.pack_start(m_userCode);
  m_boxLayout.pack_start(m_buttonsLayout);
  m_doneBtn.grab_focus();
  add(m_boxLayout);
  m_doneBtn.signal_clicked().connect(sigc::mem_fun(*this, &TokenWindow::continueLogin));
  m_cancelBtn.signal_clicked().connect(sigc::mem_fun(*this, &TokenWindow::cancel));
  show_all_children();
}

TokenWindow::~TokenWindow()
{
}

void TokenWindow::setParentWindow(MainWindow *parent)
{
  m_parent = parent;
}

void TokenWindow::showUserCode(std::string p_user_code)
{
  m_userCode.set_text(p_user_code);
}


void TokenWindow::closeAndClear()
{
  clearData();
  set_visible(false);
}

void TokenWindow::clearData()
{
    m_userCode.set_text("");
}

void TokenWindow::cancel(){
  Gtk::MessageDialog dialog(*this, "Do you want to cancel login?", 
                              false,
                              Gtk::MESSAGE_QUESTION, 
                              Gtk::BUTTONS_YES_NO);
    dialog.set_secondary_text("This action cannot be undone.");
    int result = dialog.run();

    switch(result) {
        case Gtk::RESPONSE_YES:
            m_parent->cancelLoginProcess();
            set_visible(false);
            break;
        case Gtk::RESPONSE_NO:
            break;
        default:
            break;
    }
  
}

void TokenWindow::continueLogin()
{
  m_parent->requestPkceApiKey();
}
