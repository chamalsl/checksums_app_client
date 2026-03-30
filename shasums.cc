#include <cstdlib>
#include <gtkmm/application.h>
#include <curl/curl.h>
#include "main_window.h"
#include "config.h"
#include "utils.h"

int main(int argc, char *argv[]){
  auto app = Gtk::Application::create(argc, argv, "app.checksums");
  std::unique_ptr<ChecksumsApp::Config> config = std::make_unique<ChecksumsApp::Config>();
  if (!config->initialize()){
    Utils::showError("Could not read configuration file!");
    return EXIT_FAILURE;
  }
  MainWindow main_window(std::move(config));
  curl_global_init(CURL_GLOBAL_ALL);
  return app->run(main_window);
}
