#include "token_window.h"
#include "utils.h"
#include "third_party/json_parser/json_parser.h"
#include <iostream>
#include "api.h"


TokenWindow::TokenWindow() : m_tokenLabel("Token"),
                             m_cancelBtn("Cancel"),
                             m_buttonBox(Gtk::Orientation::ORIENTATION_HORIZONTAL, 5)
{
  set_title("Login");
  
  m_userCode.set_editable(false); 
  m_userCode.set_name("user_code");
  m_formGrid.set_row_spacing(5);
  m_formGrid.set_column_spacing(5);
  m_formGrid.attach(m_tokenLabel,0,0);
  m_formGrid.attach(m_userCode,1,0);
  m_buttonBox.pack_end(m_cancelBtn,Gtk::PACK_SHRINK,8);
  m_formGrid.set_margin_top(8);
  m_formGrid.set_margin_left(5);
  m_formGrid.set_margin_right(5);
  m_formGrid.attach(m_buttonBox, 1,2,3,1);
  m_cancelBtn.grab_focus();
  add(m_formGrid);
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

void TokenWindow::cancel(){
  set_visible(false);
}
