#include "ServerBrowser.h"

int 
main(int argc, char** argv) {
    EasyServerBrowser::InternetMasterServer * ims = new EasyServerBrowser::InternetMasterServer();
    
    ims->Start("");
    
    
}
