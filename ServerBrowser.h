/* 
 * File:   ServerBrowser.h
 * Author: afaucher
 *
 * Created on August 2, 2009, 8:39 PM
 */

#ifndef _SERVERBROWSER_H
#define	_SERVERBROWSER_H

#include <SDL/SDL_net.h>
#include <map>
#include <string>
#include <list>

#include <sigc++/sigc++.h>

namespace EasyServerBrowser {

    class ServerEntry {
    public:
        typedef std::map<std::string, std::string> server_entry_param_map_t;
    private:
        server_entry_param_map_t parameters;
    public:
        ServerEntry(const server_entry_param_map_t & params);

        void Refresh();
        void Update(const server_entry_param_map_t & params);

        static server_entry_param_map_t ParseKeys(uint8_t * data, int len);

        bool GetField(const std::string & name, std::string & value) const;
        const server_entry_param_map_t & GetParams() const;
    };

    class ServerBrowser {
    public:
        typedef std::map<std::string, ServerEntry*> server_entry_map_t;
    private:
        server_entry_map_t lan_servers;
        server_entry_map_t internet_servers;

        SDLNet_SocketSet socket_set;
        UDPsocket lan_announce_socket;
        IPaddress udp_address;
        bool started;
        std::string header_string;

        static const int LAN_ANNOUNCE_UDP_PORT = 42077;

        UDPpacket * GetPacket();
        void ReturnPacket(UDPpacket * packet);
        void TryReceiveAnnouncement(UDPpacket * packet);

        static const int ANNOUNCE_RATE = 10*100;

        bool announce_server;
        int last_announce;
        int update_count;
        int announce_channel;
        ServerEntry::server_entry_param_map_t local_server_params;

        sigc::slot<void> notify_update;

    public:
        ServerBrowser();

        typedef enum {
            server_browser_type_internet,
            server_browser_type_lan,
        } server_browser_type_t;

        void AnnounceServer(ServerEntry::server_entry_param_map_t & params);
        void StopAnnouncingServer();

        void RegisterForUpdates(sigc::slot<void> slot);

        bool Start(std::string game_name_magic);
        void Stop();
        void Update();
        void Refresh(server_browser_type_t server_browser_type);
        server_entry_map_t GetList(server_browser_type_t server_browser_type);
    };

}

#endif	/* _SERVERBROWSER_H */

