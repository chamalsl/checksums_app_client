#include <gtkmm.h>

class ContacUsWindow {

    public:
        void sendMessage();
        void cancelMessage();
        bool showWindow(Gtk::Window &p_parent);

    private:
        Gtk::Window* m_contactWindow = NULL;
        Gtk::Entry* m_nameTxt;
        Gtk::Entry* m_emailTxt;
        Gtk::Entry* m_subjectTxt;
        Gtk::TextView* m_messageTxt;
        Gtk::Button* m_sendBtn;
        Gtk::Button* m_cancelBtn;
        Gtk::Button* m_loginBtn;
};