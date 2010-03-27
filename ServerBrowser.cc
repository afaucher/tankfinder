#include <SDL/SDL_net.h>

#include "ServerBrowser.h"
#include "../Util.h"
#include "../GameApp.h"

namespace EasyServerBrowser {

    ServerEntry::ServerEntry(const server_entry_param_map_t & params) :
        parameters(params)
    {

    }

    void ServerEntry::Refresh()
    {
        FAILURE("TODO");
    }

    void ServerEntry::Update(const server_entry_param_map_t & params)
    {
        FAILURE("TODO");
    }

    ServerEntry::server_entry_param_map_t ServerEntry::ParseKeys(uint8_t * data, int len) {
        return server_entry_param_map_t();
    }

    bool ServerEntry::GetField(const std::string & name, std::string & value) const
    {
        FAILURE("TODO");
        return false;
    }

    const ServerEntry::server_entry_param_map_t & ServerEntry::GetParams() const
    {
        return parameters;
    }

    ServerBrowser::ServerBrowser() :
        socket_set(NULL),
        lan_announce_socket(NULL),
        started(false),
        announce_channel(-1)
    {
        
    }

    bool ServerBrowser::Start(std::string game_name_magic) {

        int ret = 0;
        IPaddress udp_address;

        if (started) {
            WARNING("Already started");
            return false;
        }

        header_string = "easy_server_browser/";
        header_string += game_name_magic;

        ret = SDLNet_Init();
        if(ret == -1)
        {
            FAILURE("SDLNet_Init: %s",SDLNet_GetError());
            return false;
        }

        socket_set = SDLNet_AllocSocketSet(16);
        if(!socket_set) {
            FAILURE("SDLNet_AllocSocketSet: %s", SDLNet_GetError());
            return false;
        }

        lan_announce_socket = SDLNet_UDP_Open(ServerAdvertisement::LAN_ANNOUNCE_UDP_PORT);
        if (!lan_announce_socket) {
            FAILURE("SDLNet_UDP_Open: %s", SDLNet_GetError());
            return false;
        }

        ret = SDLNet_UDP_AddSocket(socket_set, lan_announce_socket);
        if (ret == -1) {
            FAILURE("SDLNet_UDP_AddSocket: %s", SDLNet_GetError());
            return false;
        }

        ret = SDLNet_ResolveHost(&udp_address,"255.255.255.255",ServerAdvertisement::LAN_ANNOUNCE_UDP_PORT);
        if(ret == -1) {
            FAILURE("SDLNet_ResolveHost: %s", SDLNet_GetError());
            return false;
        }

        INFO("Host %#08x", udp_address.host);
        //udp_address.host = INADDR_BROADCAST;

        ret = SDLNet_UDP_Bind(lan_announce_socket, -1, &udp_address);
        if (ret == -1) {
            FAILURE("SDLNet_UDP_Bind: %s", SDLNet_GetError());
            return false;
        } else {
            INFO("Bound channel %d", ret);
            announce_channel = ret;
        }

        started = true;
        INFO("Server browser started");

        return true;

    }

    void ServerBrowser::Stop() {

        if (!started) {
            WARNING("Not started");
            return;
        }
        
        INFO("Stopping server browser");

        started = false;
        if (lan_announce_socket) {
            SDLNet_UDP_Close(lan_announce_socket);
            lan_announce_socket = NULL;
        }
    }

    UDPpacket * ServerBrowser::GetPacket() {
        return SDLNet_AllocPacket(1024);
    }

    void ServerBrowser::ReturnPacket(UDPpacket * packet) {
        CHECK(packet,);
        SDLNet_FreePacket(packet);
    }

    void ServerBrowser::TryReceiveAnnouncement(UDPpacket * packet) {
        CHECK(packet,);
        
        size_t header_length = header_string.length();
        if (packet->len < (int)header_length) {
            WARNING("Short Header");
            return;
        }
        if (strncmp((char*)packet->data, header_string.c_str(), header_length) != 0) {
            WARNING("Incorrect Header");
            return;
        }
        //TODO: Parse action

        ServerEntry::server_entry_param_map_t browser_params;

        std::string name = SDLNet_ResolveIP(&packet->address);
        browser_params["name"] = name;
        INFO("name = %s", name.c_str());

        char address_text[20] = {};
        uint8_t * address_bytes = (uint8_t*)(&packet->address.host);
        snprintf(address_text, 18, "%d.%d.%d.%d",
            address_bytes[0],
            address_bytes[1],
            address_bytes[2],
            address_bytes[3]);
        browser_params["address"] = address_text;
        INFO("address = %s", address_text);

        char port_text[20] = {};
        snprintf(port_text, 10, "%u", SDL_SwapBE16(packet->address.port));
        browser_params["port"] = port_text;
        INFO("port = %s", port_text);

        std::string key = address_text;
        key += ":";
        key += port_text;

        ServerEntry::server_entry_param_map_t server_data_keys =
            ServerEntry::ParseKeys(&packet->data[header_length], packet->len - header_length);

        FAILURE("FIXME");
        server_data_keys["address"] = address_text;

        server_entry_map_t::iterator server_itr = lan_servers.find(key);
        if (server_itr == lan_servers.end()) {
            INFO("New server");

            lan_servers[key] = new ServerEntry(server_data_keys);
        } else {
            INFO("Server update");

            ServerEntry * se = server_itr->second;
            se->Update(server_data_keys);
        }
        notify_update();
    }

    void ServerBrowser::Update() {
        int ret = 0;

        if (!started) {
            return;
        }

        ret = SDLNet_CheckSockets(socket_set, 0);
        if (ret == -1) {
            FAILURE("SDLNet_CheckSockets: %s", SDLNet_GetError());
            return;
        }

        if (ret > 0) {
            if (SDLNet_SocketReady(lan_announce_socket)) {
                INFO("Ready");
                UDPpacket * packet = GetPacket();
                if (packet) {
                    ret = SDLNet_UDP_Recv(lan_announce_socket, packet);
                    if ( ret == -1 ) {
                        FAILURE("SDLNet_UDP_Recv: %s", SDLNet_GetError());
                    } else if ( ret ) {
                        TryReceiveAnnouncement(packet);
                    }
                    ReturnPacket(packet);
                }
            }
        }

        
    }

    void ServerBrowser::Refresh(server_browser_type_t server_browser_type) {
        switch (server_browser_type) {
            case server_browser_type_lan:
                FAILURE("Cleanup");
                lan_servers.clear();
                break;
            case server_browser_type_internet:
                internet_servers.clear();
                break;
        }
    }

    ServerBrowser::server_entry_map_t ServerBrowser::GetList(server_browser_type_t server_browser_type) {

        //FAILURE("TODO");

        switch (server_browser_type) {
            case server_browser_type_lan:
                return lan_servers;
            case server_browser_type_internet:
                return internet_servers;
        }
        return server_entry_map_t();
    }

    void ServerBrowser::RegisterForUpdates(sigc::slot<void> slot) {
        notify_update = slot;
    }

    ServerAdvertisement::ServerAdvertisement() :
        lan_announce_socket(NULL),
        started(false),
        last_announce(0),
        announce_channel(-1),
        local_server_params(),
        header_string()
    {
        
    }

    bool ServerAdvertisement::Start(
        std::string game_name_magic,
        ServerEntry::server_entry_param_map_t & params)
    {
        int ret = 0;
        IPaddress udp_address;

        local_server_params = params;

        if (started) {
            WARNING("Server advertisement already started");
            return false;
        }

        header_string = "easy_server_browser/";
        header_string += game_name_magic;

        ret = SDLNet_Init();
        if(ret == -1)
        {
            FAILURE("SDLNet_Init: %s",SDLNet_GetError());
            return false;
        }

        lan_announce_socket = SDLNet_UDP_Open(0);
        if (!lan_announce_socket) {
            FAILURE("SDLNet_UDP_Open: %s", SDLNet_GetError());
            return false;
        }

        ret = SDLNet_ResolveHost(&udp_address,"255.255.255.255",ServerAdvertisement::LAN_ANNOUNCE_UDP_PORT);
        if(ret == -1) {
            FAILURE("SDLNet_ResolveHost: %s", SDLNet_GetError());
            return false;
        }

        INFO("Host %#08x", udp_address.host);
        //udp_address.host = INADDR_BROADCAST;

        ret = SDLNet_UDP_Bind(lan_announce_socket, -1, &udp_address);
        if (ret == -1) {
            FAILURE("SDLNet_UDP_Bind: %s", SDLNet_GetError());
            return false;
        } else {
            INFO("Bound channel %d", ret);
            announce_channel = ret;
        }

        started = true;
        INFO("Server anouncer started");

        return true;
    }

    void ServerAdvertisement::Stop() {
        if (!started) {
            return;
        }
        started = false;
        if (lan_announce_socket) {
            SDLNet_UDP_Close(lan_announce_socket);
            lan_announce_socket = NULL;
        }
        local_server_params.clear();
    }

    void ServerAdvertisement::Update() {
        if (!started)
            return;

        //TODO: Try announce
        if (last_announce + ANNOUNCE_RATE <= update_count)
        {
            last_announce = update_count;
            UDPpacket * packet = GetPacket();
            if (packet) {

                size_t header_length = header_string.length();
                memcpy(packet->data, header_string.c_str(), header_length);
                packet->len = header_length;

                SDLNet_UDP_Send(lan_announce_socket, announce_channel, packet);

                ReturnPacket(packet);
            }
        }
        update_count++;
    }

    UDPpacket * ServerAdvertisement::GetPacket() {
        return SDLNet_AllocPacket(1024);
    }

    void ServerAdvertisement::ReturnPacket(UDPpacket * packet) {
        CHECK(packet,);
        SDLNet_FreePacket(packet);
    }

}
