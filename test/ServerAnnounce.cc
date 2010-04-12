#include "ServerBrowser.h"
#include "ServerBrowserUtil.h"

int 
main(int argc, char** argv) {
    EasyServerBrowser::ServerAdvertisement * adv = new EasyServerBrowser::ServerAdvertisement();
    
    EasyServerBrowser::ServerEntry::server_entry_param_map_t params;
    
    params["name"] = "A cool game name"; //server name, optional but recommended
    params["port"] = "10000"; //port to connect to join the game, manditory
    
    adv->Start("tankfind", params);
    
    while (1) {
        usleep(10000);
        adv->Update();
    }
}
