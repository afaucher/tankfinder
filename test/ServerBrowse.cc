#include "ServerBrowser.h"
#include "ServerBrowserUtil.h"

void ServerListUpdateAvailable(EasyServerBrowser::ServerBrowser * browse)
{
    INFO("Update");
}

int 
main(int argc, char** argv) {
    EasyServerBrowser::ServerBrowser * browse = new EasyServerBrowser::ServerBrowser();
    
    sigc::slot<void> slot = sigc::bind<EasyServerBrowser::ServerBrowser *>(
        sigc::ptr_fun(&ServerListUpdateAvailable),
        browse);
    browse->RegisterForUpdates(slot);
    
    browse->Start("tankfind");
    
    while (1) {
        usleep(10000);
        browse->Update();
    }
}
