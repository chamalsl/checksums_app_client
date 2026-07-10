#include "contactus_window.h"
#include "api.h"
#include "utils.h"
#include <iostream>

void ContacUsWindow::init()
{
    if (m_contactWindow == NULL) {
        auto builder = Gtk::Builder::create_from_resource("/ui/contact.ui");
        builder->get_widget("contact_window", m_contactWindow);
        m_contactWindow->set_modal(true);
        m_contactWindow->set_visible(false);
        builder->get_widget("cancel_button", m_cancelBtn);
        builder->get_widget("send_button", m_sendBtn);
        builder->get_widget("name_entry", m_nameTxt);
        builder->get_widget("email_entry", m_emailTxt);
        builder->get_widget("subject_entry", m_subjectTxt);
        builder->get_widget("message_entry", m_messageTxt);
        m_cancelBtn->signal_clicked().connect(sigc::mem_fun(*this, &ContacUsWindow::cancelMessage));
        m_sendBtn->signal_clicked().connect(sigc::mem_fun(*this, &ContacUsWindow::sendMessage));
    }
}


void ContacUsWindow::sendMessage()
{
    Glib::RefPtr<Gtk::TextBuffer> buffer = m_messageTxt->get_buffer();
    Glib::ustring message = buffer->get_text();

    std::string validation_errors = "";

    if (!m_emailTxt->get_text().empty() && !Utils::isValidEmail(m_emailTxt->get_text())) {
        validation_errors.append("Email is invalid\n");
    }

    if (m_subjectTxt->get_text().empty()) {
        validation_errors.append("Subject is required!\n");
    }

    if (message.empty()) {
        validation_errors.append("Message is required!\n");
    }

    if (message.length() > 2000) {
        validation_errors.append("Message cannot have more than 2000 characters!\n");
    }

    if (!validation_errors.empty()){
        Utils::showError(validation_errors);
        return;
    }

    std::pair<short, std::string> result = Api::sendContactUsMessage(m_nameTxt->get_text(),m_emailTxt->get_text(),m_subjectTxt->get_text(),message);

    if (result.first == 200) {
        Utils::showMessage("Message Sent!", GTK_MESSAGE_INFO);
        m_contactWindow->set_visible(false);

    } else {
        Utils::showError("Could not send message. Please try again later!");
    }
}

void ContacUsWindow::cancelMessage()
{
    m_contactWindow->set_visible(false);
}

bool ContacUsWindow::showWindow(Gtk::Window &p_parent)
{ 
    init();

    if (!showAllCalled) {
        m_contactWindow->show_all();
        m_contactWindow->set_transient_for(p_parent);
        showAllCalled = true;
    }
    
    m_contactWindow->set_visible(true);
    return true;
}

void ContacUsWindow::setDefaultValuesToRequestNewSoftware()
{
    init();
    m_subjectTxt->set_text("Request to add new Software");
    Glib::RefPtr<Gtk::TextBuffer> buffer = m_messageTxt->get_buffer();
    buffer->set_text("These software are not available in our system.\n"
        "Please add them\n\n"
        "1). Name of Software"
    );

}
