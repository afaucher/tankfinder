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


#include <sigc++/sigc++.h>

namespace EasyServerBrowser {

    class ServerEntry {
    public:
        typedef std::map<std::string, std::string> server_entry_param_map_t;
    private:
        server_entry_param_map_t parameters;
    public:
        ServerEntry(const server_entry_param_map_t & params);
        
        bool GetField(const std::string & name, std::string & value) const;
        bool GetField(const std::string & name, int & value) const;
        const server_entry_param_map_t & GetParams() const;
        
        void Add(const std::string & key, const std::string & value);
        void Add(const std::string & key, int value);
        void Update(const server_entry_param_map_t & params);
        
        static std::string GetJSON(const server_entry_param_map_t & parameters);
    };



    class ServerBrowser {
    public:
        typedef std::map<std::string, ServerEntry*> server_entry_map_t;
    private:
        server_entry_map_t lan_servers;
        server_entry_map_t internet_servers;
        //this set is populated under internal mutex by the server list download thread
        //it is swapped in on the next update call
        server_entry_map_t pending_internet_servers;

        SDLNet_SocketSet socket_set;
        UDPsocket lan_announce_socket;
        
        bool started;
        std::string header_string;
        std::string game_name_magic;
    
        bool use_http;

        int announce_channel;

        sigc::slot<void> notify_update;

        UDPpacket * GetPacket();
        void ReturnPacket(UDPpacket * packet);
        
        void TryReceiveAnnouncement(UDPpacket * packet);
        static void * DownloadMasterServerList(void* context);
        
        

    public:
        ServerBrowser();
        
        static server_entry_map_t ParseServerList(const uint8_t * buffer, uint32_t length);

        typedef enum {
            server_browser_type_internet,
            server_browser_type_lan,
        } server_browser_type_t;
        
        void SetUseHTTP(bool use_http);
        
        //request the passed function be called when the server list has been updated
        void RegisterForUpdates(sigc::slot<void> slot);

        bool Start(std::string game_name_magic);
        void Stop();
        void Update();
        void Refresh(server_browser_type_t server_browser_type);
        server_entry_map_t GetList(server_browser_type_t server_browser_type);
        
        static void ClearServerEntryMap(server_entry_map_t & map);
    };

    class ServerAdvertisement {
    private:
        UDPsocket lan_announce_socket;

        bool started;
        time_t last_announce;
        
        time_t last_internet_announce;
        bool announce_internet;
        bool use_http;

        int announce_channel;
        int internet_announce_channel;

        ServerEntry::server_entry_param_map_t local_server_params;

        static const int ANNOUNCE_RATE = 5;
        static const int INTERNET_ANNOUNCE_RATE = 60;
        //std::string header_string;
        std::string game_name_magic;
        std::string json_cache;

        UDPpacket * GetPacket();
        void ReturnPacket(UDPpacket * packet);
        
        static void * HTTPAnnounce(void * context);
        
    public:
        ServerAdvertisement();

        static const int LAN_ANNOUNCE_UDP_PORT = 42077;
    
        void SetAnnounceInternet(bool announce_internet);
        void SetAnnounceHTTP(bool use_http);

        bool Start(
            std::string game_name_magic,
            ServerEntry::server_entry_param_map_t & params);
        void Stop();
        void Update();
        void UpdateAdvertisement(const ServerEntry::server_entry_param_map_t & params);
    };
    
    class InternetMasterServer {
    private:
        UDPsocket internet_collect_socket;
        TCPsocket server_list_accept_socket;
        SDLNet_SocketSet socket_set;
        
        //game name, serverlist
        typedef std::map<std::string, ServerBrowser::server_entry_map_t*> game_server_list_map_t;
        
        game_server_list_map_t game_server_list_map;
        
        std::string game_name_magic;
        
        void TryReceiveAnnouncement();
        UDPpacket * GetPacket();
        void ReturnPacket(UDPpacket * packet);
        
        void Update();
        
        void TryReceiveAnnouncement(UDPpacket * packet);
        void HandleAcceptedSocket(TCPsocket client_tcp_socket);
        
        //remove expired servers from the list
        void Purge();
        
        static std::string GetJSON(const ServerBrowser::server_entry_map_t & map);
        
    public:
        InternetMasterServer();
        
        static const int INTERNET_MASTER_SERVER_REGISTER_PORT = 42078;
        static const int INTERNET_MASTER_SERVER_LIST_PORT = 42079;
        static const int INTERNET_MASTER_SERVER_REFRESH_LIMIT = 60;
        
        //game_name_magic: null for no filter
        //does not return
        bool Start(
            std::string game_name_magic);
        
    };

}

#endif	/* _SERVERBROWSER_H */

