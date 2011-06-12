#include <pthread.h>
#include <SDL/SDL_net.h>
#include <assert.h>
#include <list>
#include <vector>

#include "ServerBrowser.h"
#include "ServerBrowserUtil.h"

#include "json/JSON_parser.h"

#define EASY_SERVER_MAGIC "easy_server_browser/"
#define EASY_SERVER_MAGIC_LENGTH strlen(EASY_SERVER_MAGIC)
//#define IMSL_ADDRESS "afaucher.gotdns.com"
#define IMSL_ADDRESS "tankfinderhttp.sourceforge.net"
//#define IMSL_ADDRESS "localhost"
#define IMSL_GET_SERVER_LIST_PATH "/actions/server_list.php"
#define IMSL_ANNOUNCE_SERVER_PATH "/actions/announce_server.php"

#ifndef _GNU_SOURCE
static void *
memmem(
    const void *haystack,
    size_t haystack_len,
    const void *needle,
    size_t needle_len )
{
    const char *begin;
    const char *const last_possible
    = ( const char * ) haystack + haystack_len - needle_len;

    if ( needle_len == 0 )
        /* The first occurrence of the empty string is deemed to occur at
           the beginning of the string.  */
        return ( void * ) haystack;

    /* Sanity check, otherwise the loop might search through the whole
       memory.  */
    if ( __builtin_expect( haystack_len < needle_len, 0 ) )
        return NULL;

    for ( begin = ( const char * ) haystack; begin <= last_possible; ++begin )
        if ( begin[0] == (( const char * ) needle )[0] &&
                !memcmp(( const void * ) &begin[1],
                        ( const void * )(( const char * ) needle + 1 ),
                        needle_len - 1 ) )
            return ( void * ) begin;

    return NULL;
}
#endif


namespace EasyServerBrowser
{

    static pthread_mutex_t pending_internet_servers_mutex = PTHREAD_MUTEX_INITIALIZER;

    ServerEntry::ServerEntry( const server_entry_param_map_t & params ) :
            parameters( params )
    {

    }

    void ServerEntry::Update( const server_entry_param_map_t & params )
    {
        server_entry_param_map_t::const_iterator itr = params.begin();
        for ( ; itr != params.end(); itr++ )
        {
            parameters[itr->first] = itr->second;
        }
    }

    bool ServerEntry::GetField( const std::string & name, std::string & value ) const
    {
        server_entry_param_map_t::const_iterator itr = parameters.find( name );
        if ( itr == parameters.end() ) return false;
        value = itr->second;
        return true;
    }

    bool ServerEntry::GetField( const std::string & name, int & value ) const
    {
        server_entry_param_map_t::const_iterator itr = parameters.find( name );
        if ( itr == parameters.end() ) return false;
        value = atoi( itr->second.c_str() );
        return true;
    }

    const ServerEntry::server_entry_param_map_t & ServerEntry::GetParams() const
    {
        return parameters;
    }

    std::string ServerEntry::GetJSON( const server_entry_param_map_t & parameters )
    {
        std::string json = "{";

        server_entry_param_map_t::const_iterator itr = parameters.begin();

        bool first = true;
        for ( ; itr != parameters.end(); itr++ )
        {
            if ( first )
            {
                first = false;
            }
            else
            {
                json += ",";
            }
            json += "\"";
            json += itr->first;
            json += "\":\"";
            json += itr->second;
            json += "\"";
        }

        json += "}";

        return json;
    }

    void ServerEntry::Add( const std::string & key, const std::string & value )
    {
        parameters[key] = value;
    }

    void ServerEntry::Add( const std::string & key, int value )
    {
        char buffer[32];
        int printed_len = 0;
        snprintf( buffer, 32, "%d%n", value, &printed_len );
        parameters[key] = std::string( buffer );
    }

    ServerBrowser::ServerBrowser() :
            lan_servers(),
            internet_servers(),
            pending_internet_servers(),
            socket_set( NULL ),
            lan_announce_socket( NULL ),
            started( false ),
            use_http( true ),
            announce_channel( -1 )
    {
    }

    typedef struct json_context
    {
        std::list<ServerEntry*> * se_list;
        std::string key;
    } json_context_t;

    static int json_callback( void* ctx, int type, const struct JSON_value_struct* value )
    {
        CHECK( ctx,0 );

        json_context_t * c = ( json_context_t* )ctx;
        std::list<ServerEntry*> * se_list = c->se_list;

        /*
        array(
            object("server", array(params)),
            object("server", array(params)),
            )

        */

        //INFO("Type: %d Value: %p", type, value);

        switch ( type )
        {
            case JSON_T_ARRAY_BEGIN:
                //INFO("<array>");
                return 1;
            case JSON_T_ARRAY_END:
                //INFO("</array>");
                return 1;
            case JSON_T_OBJECT_BEGIN:
            {
                //INFO("<obj>");
                ServerEntry::server_entry_param_map_t params;
                ServerEntry * se = new ServerEntry( params );
                se_list->push_back( se );
                return 1;
            }
            case JSON_T_OBJECT_END:
                //INFO("</obj>");
                return 1;
        }

        if ( value )
        {
            ServerEntry * se = NULL;
            switch ( type )
            {
                case JSON_T_INTEGER:
                case JSON_T_FLOAT:
                case JSON_T_STRING:
                    if ( !c->key.length() )
                    {
                        FAILURE( "Invalid key for data" );
                        return 0;
                    }
                    if ( se_list->size() )
                    {
                        se = se_list->back();
                        if ( !se )
                        {
                            FAILURE( "Bad server list" );
                            return 0;
                        }
                    }
                    else
                    {
                        FAILURE( "No server object found" );
                        return 0;
                    }
                    break;
                case JSON_T_KEY:
                    //INFO("Key \"%.*s\"", (int)value->vu.str.length, value->vu.str.value);
                    c->key = std::string( value->vu.str.value, value->vu.str.length );
                    return 1;
                default:
                    FAILURE( "Unknown type" );
                    return 0;
            }
            switch ( type )
            {
                case JSON_T_INTEGER:
                    //INFO("Int %ld", value->vu.integer_value);
                    break;
                case JSON_T_FLOAT:
                    //INFO("Float %f", value->vu.float_value);
                    break;
                case JSON_T_STRING:
                    //INFO("String \"%.*s\"", (int)value->vu.str.length, value->vu.str.value);
                    se->Add( c->key, std::string( value->vu.str.value, value->vu.str.length ) );
                    break;
                default:
                    FAILURE( "Unknown type" );
                    return 0;
            }
            c->key = "";
        }

        return 1;
    }

    static bool parse_server_list( std::list<ServerEntry*> & se_list, const uint8_t * buffer, uint32_t length )
    {
        JSON_config c;
        JSON_parser p;

        int ret = 0;
        bool parsed = true;
        json_context_t ctx =
        {
            &se_list,
            std::string(),
        };

        init_JSON_config( &c );
        c.callback = json_callback;
        c.callback_ctx = &ctx;

        p = new_JSON_parser( &c );

        uint32_t i = 0;
        for ( i = 0; i < length; i++ )
        {
            ret = JSON_parser_char( p, buffer[i] );
            if ( !ret )
            {
                FAILURE( "JSON error @ %d '0x%.02x \"%s\"", i, buffer[i], ( char* )&buffer[i] );
                parsed = false;
                break;
            }
        }

        if ( parsed )
        {
            ret = JSON_parser_done( p );
            if ( !ret )
            {
                FAILURE( "JSON error @ done" );
                parsed = false;
            }
        }

        delete_JSON_parser( p );

        return parsed;
    }

    ServerBrowser::server_entry_map_t ServerBrowser::ParseServerList( const uint8_t * buffer, uint32_t length )
    {
        ServerBrowser::server_entry_map_t result;

        CHECK( buffer,result );
        CHECK( length,result );

        std::list<ServerEntry*> se_list;
        bool parsed = parse_server_list( se_list, buffer, length );

        if ( !parsed ) return result;
        //FAILURE("TODO");

        std::list<ServerEntry*>::iterator itr = se_list.begin();
        for ( ; itr != se_list.end(); itr++ )
        {
            ServerEntry * se = *itr;
            //INFO("%s",se->GetJSON().c_str());
            std::string address;
            std::string port;

            if ( se->GetField( "address", address )
                    && se->GetField( "port", port ) )
            {
                std::string key = address;
                key += ":";
                key += port;
                result[key] = se;
            }
            else
            {
                FAILURE( "Unable to find address and port in ServerEntry" );
                delete( se );
                se = NULL;
            }
        }

        return result;
    }

    ServerEntry::server_entry_param_map_t ServerBrowser::GetServerParams( const uint8_t * buffer, uint32_t length )
    {
        ServerEntry::server_entry_param_map_t result;

        CHECK( buffer,result );
        CHECK( length,result );

        std::list<ServerEntry*> se_list;
        bool parsed = parse_server_list( se_list, buffer, length );

        if ( !parsed ) return result;
        //FAILURE("TODO");

        std::list<ServerEntry*>::iterator itr = se_list.begin();

        if ( itr != se_list.end() )
        {
            ServerEntry * se = *itr;

            result = se->GetParams();
        }
        itr = se_list.begin();
        for ( ; itr != se_list.end(); itr++ )
        {
            delete( *itr );
        }

        return result;
    }

    bool ServerBrowser::Start( std::string game_name_magic )
    {

        int ret = 0;
        IPaddress udp_address;

        if ( started )
        {
            WARNING( "Already started" );
            return false;
        }

        header_string = EASY_SERVER_MAGIC;
        header_string += game_name_magic;
        this->game_name_magic = game_name_magic;

        ret = SDLNet_Init();
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_Init: %s",SDLNet_GetError() );
            return false;
        }

        socket_set = SDLNet_AllocSocketSet( 16 );
        if ( !socket_set )
        {
            FAILURE( "SDLNet_AllocSocketSet: %s", SDLNet_GetError() );
            return false;
        }

        lan_announce_socket = SDLNet_UDP_Open( ServerAdvertisement::LAN_ANNOUNCE_UDP_PORT );
        if ( !lan_announce_socket )
        {
            FAILURE( "SDLNet_UDP_Open: %s", SDLNet_GetError() );
            return false;
        }

        ret = SDLNet_UDP_AddSocket( socket_set, lan_announce_socket );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_UDP_AddSocket: %s", SDLNet_GetError() );
            return false;
        }

        ret = SDLNet_ResolveHost( &udp_address,"255.255.255.255",ServerAdvertisement::LAN_ANNOUNCE_UDP_PORT );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_ResolveHost: %s", SDLNet_GetError() );
            return false;
        }

        INFO( "Host %#08x", udp_address.host );
        //udp_address.host = INADDR_BROADCAST;

        ret = SDLNet_UDP_Bind( lan_announce_socket, -1, &udp_address );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_UDP_Bind: %s", SDLNet_GetError() );
            return false;
        }
        else
        {
            INFO( "Bound channel %d", ret );
            announce_channel = ret;
        }

        started = true;
        INFO( "Server browser started" );

        return true;

    }

    void ServerBrowser::Stop()
    {

        if ( !started )
        {
            WARNING( "Not started" );
            return;
        }

        INFO( "Stopping server browser" );

        started = false;
        if ( lan_announce_socket )
        {
            SDLNet_UDP_Close( lan_announce_socket );
            lan_announce_socket = NULL;
        }
    }

    UDPpacket * ServerBrowser::GetPacket()
    {
        return SDLNet_AllocPacket( 1024 );
    }

    void ServerBrowser::ReturnPacket( UDPpacket * packet )
    {
        CHECK( packet, );
        SDLNet_FreePacket( packet );
    }

    void ServerBrowser::TryReceiveAnnouncement( UDPpacket * packet )
    {
        CHECK( packet, );

        size_t header_length = header_string.length();
        if ( packet->len < ( int )header_length )
        {
            WARNING( "Short Header" );
            return;
        }
        if ( strncmp(( char* )packet->data, header_string.c_str(), header_length ) != 0 )
        {
            WARNING( "Incorrect Header" );
            return;
        }
        //TODO: Parse action

        ServerEntry::server_entry_param_map_t browser_params;

        char address_text[20] = {};
        uint8_t * address_bytes = ( uint8_t* )( &packet->address.host );
        snprintf( address_text, 18, "%d.%d.%d.%d",
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3] );
        browser_params["address"] = address_text;
        //INFO("address = %s", address_text);
        
        const char * resolvedHostName = SDLNet_ResolveIP( &packet->address );
        std::string name = "";
        if (resolvedHostName != NULL) {
            name = resolvedHostName;
        } else {
            //This happens when the host doesn't announce it's name on the network or respond to queries.
            WARNING("Failed to resolve hostname from IP for discovered server");
            name = address_text;
        }
        browser_params["hostname"] = name;
        //INFO("name = %s", name.c_str());

        //char port_text[20] = {};
        //snprintf(port_text, 10, "%u", SDL_SwapBE16(packet->address.port));
        //browser_params["port"] = port_text;
        //INFO("recv port = %s", port_text);

        std::string key = address_text;
        key += ":";
        //key += port_text;

        if (( packet->len - header_length ) <= 1 )
        {
            FAILURE( "No details availalbe" );
            return;
        }

        header_length += 1;

        //INFO("%.*s", (packet->len - header_length), &packet->data[header_length]);

        std::list<ServerEntry*> se_list;
        bool parsed = parse_server_list(
                    se_list,
                    &packet->data[header_length],
                    packet->len - header_length );
        if ( !parsed )
        {
            FAILURE( "Failed to parse details" );
            return;
        }

        bool updated_list = false;

        std::list<ServerEntry*>::iterator itr = se_list.begin();
        for ( ; itr != se_list.end(); itr++ )
        {
            ServerEntry * se = *itr;

            std::string port;
            bool found_port = se->GetField( "port", port );
            if ( !found_port )
            {
                FAILURE( "Needed port" );
                delete( se );
                continue;
            }

            se->Add( "address", address_text );

            std::string se_key = key;
            se_key += port;

            updated_list = true;

            server_entry_map_t::iterator server_itr = lan_servers.find( se_key );
            if ( server_itr == lan_servers.end() )
            {
                INFO( "New server: %s", se_key.c_str() );

                lan_servers[se_key] = se;
            }
            else
            {
                INFO( "Server update for: %s", se_key.c_str() );
                ServerEntry * old = server_itr->second;
                delete( old );
                lan_servers[se_key] = se;
            }
        }

        if ( updated_list )
        {
            notify_update();
        }

        /*

        ServerEntry::server_entry_param_map_t::iterator port_itr = server_data_keys.find("port");
        if (port_itr != server_data_keys.end()) {
            key += port_itr->second;
        } else {
            ServerEntry::server_entry_param_map_t::iterator port_itr = server_data_keys.begin();
            for (; port_itr != server_data_keys.end(); port_itr++) {
                INFO("%s %s", port_itr->first.c_str(), port_itr->second.c_str());
            }
            FAILURE("Needed port");
            return;
        }

        server_data_keys["address"] = address_text;

        server_entry_map_t::iterator server_itr = lan_servers.find(key);
        if (server_itr == lan_servers.end()) {
            INFO("New server");

            lan_servers[key] = new ServerEntry(server_data_keys);
        } else {
            INFO("Server update");

            ServerEntry * se = server_itr->second;
            se->Update(server_data_keys);
        }*/

    }

    void ServerBrowser::Update()
    {
        int ret = 0;

        if ( !started )
        {
            return;
        }

        ret = SDLNet_CheckSockets( socket_set, 0 );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_CheckSockets: %s", SDLNet_GetError() );
            return;
        }

        if ( ret > 0 )
        {
            if ( SDLNet_SocketReady( lan_announce_socket ) )
            {
                UDPpacket * packet = GetPacket();
                if ( packet )
                {
                    ret = SDLNet_UDP_Recv( lan_announce_socket, packet );
                    if ( ret == -1 )
                    {
                        FAILURE( "SDLNet_UDP_Recv: %s", SDLNet_GetError() );
                    }
                    else if ( ret )
                    {
                        TryReceiveAnnouncement( packet );
                    }
                    ReturnPacket( packet );
                }
            }
        }

        bool updated = false;
        pthread_mutex_lock( &pending_internet_servers_mutex );

        if ( pending_internet_servers.size() )
        {
            INFO( "Updating server map" );
            ClearServerEntryMap( internet_servers );
            internet_servers = pending_internet_servers;
            pending_internet_servers.clear();
            updated = true;
        }

        pthread_mutex_unlock( &pending_internet_servers_mutex );

        if ( updated )
        {
            notify_update();
        }


    }

    void ServerBrowser::ClearServerEntryMap( server_entry_map_t & map )
    {
        server_entry_map_t::iterator itr = map.begin();
        for ( ; itr != map.end(); itr++ )
        {
            ServerEntry * se = itr->second;
            if ( !se ) continue;
            delete( se );
        }
        map.clear();
    }

    void ServerBrowser::SetUseHTTP( bool use_http )
    {
        this->use_http = use_http;
    }

    void * ServerBrowser::DownloadMasterServerList( void* context )
    {

        ServerBrowser * sb = ( ServerBrowser* )context;
        IPaddress ip;
        int ret;
        const char * master_list_server_address = IMSL_ADDRESS;
        const char * master_server_http_file = IMSL_GET_SERVER_LIST_PATH;
        uint16_t port = InternetMasterServer::INTERNET_MASTER_SERVER_LIST_PORT;

        CHECK( sb,NULL );

        if ( sb->use_http )
        {
            port = 80;
        }

        ret = SDLNet_ResolveHost( &ip,
                master_list_server_address,
                port );
        if ( ret==-1 )
        {
            FAILURE( "SDLNet_ResolveHost: %s", SDLNet_GetError() );
            return NULL;;
        }

        TCPsocket  server_list_socket = SDLNet_TCP_Open( &ip );
        if ( !server_list_socket )
        {
            FAILURE( "SDLNet_TCP_Open: %s", SDLNet_GetError() );
            perror( "SDLNet_TCP_Open" );
            return false;
        }

        uint8_t server_list_buffer[64*1024] = {};
        size_t buffer_size = 64*1024;
        size_t offset = 0;

        if ( sb->use_http )
        {
            char http_request_header[1024];
#define HTTP_LF "\r\n"
            snprintf( http_request_header,
                    1024,
                    "GET %s?game=%s HTTP/1.1" HTTP_LF
                    "Host: %s" HTTP_LF
                    "Accept: text/html" HTTP_LF
                    HTTP_LF,
                    master_server_http_file,
                    sb->game_name_magic.c_str(),
                    master_list_server_address );
            //INFO("%s", http_request_header);
            offset = 0;
            do
            {
                ret = SDLNet_TCP_Send( server_list_socket, &http_request_header[offset], 1024-offset );
                if ( ret <= 0 )
                {
                    if ( ret < 0 )
                    {
                        FAILURE( "SDLNet_TCP_Send: %s", SDLNet_GetError() );
                    }
                    break;
                }
                offset += ret;
            }
            while ( ret > 0 && (( 1024-offset ) > 0 ) );
        }

        offset = 0;
        do
        {
            ret = SDLNet_TCP_Recv( server_list_socket, &server_list_buffer[offset], buffer_size-offset );
            if ( ret <= 0 )
            {
                if ( ret < 0 )
                {
                    FAILURE( "SDLNet_TCP_Recv: %s", SDLNet_GetError() );
                }
                break;
            }
            offset += ret;

        }
        while ( ret > 0 && (( buffer_size-offset ) > 0 ) );

        uint8_t * json_start = server_list_buffer;
        size_t json_size = offset;

        if ( sb->use_http )
        {
            if ( memcmp(( const char * )json_start, "HTTP", std::min( json_size, strlen( "HTTP" ) ) ) == 0 )
            {
                INFO( "HTTP response found" );

                const char * http_header_end_string = HTTP_LF HTTP_LF;
                void * http_header_end = memmem( json_start, json_size,
                        http_header_end_string, strlen( http_header_end_string ) );

                if ( !http_header_end )
                {
                    FAILURE( "Failed to find end of http header" );
                    return NULL;
                }

                size_t header_length = ( uint8_t* )http_header_end - json_start;
                header_length += strlen( http_header_end_string );
                json_start += header_length;
                json_size -= header_length;
            }
            else
            {
                FAILURE( "Failed to find HTTP response" );
                return NULL;
            }
        }

        INFO( "\"%*s\"", ( int )json_size, json_start );

        server_entry_map_t internet_servers = EasyServerBrowser::ServerBrowser::ParseServerList(
                    json_start,
                    json_size );

        pthread_mutex_lock( &pending_internet_servers_mutex );

        ClearServerEntryMap( sb->pending_internet_servers );
        sb->pending_internet_servers = internet_servers;

        pthread_mutex_unlock( &pending_internet_servers_mutex );

        return NULL;
    }

    typedef void *( *pthread_callback_t )( void * );

    int
    pthread_create_detached(
        pthread_callback_t callback,
        void * context )
    {
        pthread_attr_t pthread_attr;
        //in detach the id is invalid
        pthread_t pthread_id;

        int attr_init_result = pthread_attr_init( &pthread_attr );
        if ( attr_init_result != 0 ) return attr_init_result;

        int attr_set_result = pthread_attr_setdetachstate( &pthread_attr, PTHREAD_CREATE_DETACHED );
        assert( attr_set_result == 0 );

        int pthread_create_result = pthread_create( &pthread_id, &pthread_attr, callback, context );

        if ( pthread_create_result != 0 )
        {
            FAILURE( "result: %d", pthread_create_result );
        }

        pthread_attr_destroy( &pthread_attr );

        return pthread_create_result;
    }

    void ServerBrowser::Refresh( server_browser_type_t server_browser_type )
    {
        switch ( server_browser_type )
        {
            case server_browser_type_lan:
                ClearServerEntryMap( lan_servers );
                break;
            case server_browser_type_internet:
            {
                ClearServerEntryMap( internet_servers );
                pthread_create_detached( ServerBrowser::DownloadMasterServerList, this );
                break;
            }
        }
    }

    ServerBrowser::server_entry_map_t ServerBrowser::GetList( server_browser_type_t server_browser_type )
    {

        switch ( server_browser_type )
        {
            case server_browser_type_lan:
                return lan_servers;
            case server_browser_type_internet:
                return internet_servers;
            default:
                return server_entry_map_t();
        }
    }

    void ServerBrowser::RegisterForUpdates( sigc::slot<void> slot )
    {
        notify_update = slot;
    }

    ServerAdvertisement::ServerAdvertisement() :
            lan_announce_socket( NULL ),
            started( false ),
            last_announce( 0 ),
            last_internet_announce( 0 ),
            announce_internet( true ),
            use_http( true ),
            announce_channel( -1 ),
            internet_announce_channel( -1 ),
            local_server_params(),
            game_name_magic()
    {

    }

    void ServerAdvertisement::SetAnnounceInternet( bool announce_internet )
    {
        this->announce_internet = announce_internet;
    }

    void ServerAdvertisement::SetAnnounceHTTP( bool use_http )
    {
        this->use_http = use_http;
    }

    void ServerAdvertisement::UpdateAdvertisement( const ServerEntry::server_entry_param_map_t & params )
    {
        local_server_params = params;

        json_cache = "[";
        json_cache += ServerEntry::GetJSON( local_server_params );
        json_cache += "]";

        last_internet_announce = 0;
        last_announce = 0;
    }

    bool ServerAdvertisement::Start(
        std::string game_name_magic,
        ServerEntry::server_entry_param_map_t & params )
    {
        int ret = 0;
        IPaddress udp_address;
        IPaddress internet_udp_address;

        this->game_name_magic = game_name_magic;

        local_server_params = params;

        if ( started )
        {
            WARNING( "Server advertisement already started" );
            return false;
        }


        ret = SDLNet_Init();
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_Init: %s",SDLNet_GetError() );
            return false;
        }

        lan_announce_socket = SDLNet_UDP_Open( 0 );
        if ( !lan_announce_socket )
        {
            FAILURE( "SDLNet_UDP_Open: %s", SDLNet_GetError() );
            return false;
        }

        ret = SDLNet_ResolveHost( &udp_address,"255.255.255.255",ServerAdvertisement::LAN_ANNOUNCE_UDP_PORT );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_ResolveHost: %s", SDLNet_GetError() );
            return false;
        }

        INFO( "Host %#08x", udp_address.host );

        ret = SDLNet_ResolveHost( &internet_udp_address,IMSL_ADDRESS,InternetMasterServer::INTERNET_MASTER_SERVER_REGISTER_PORT );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_ResolveHost: %s", SDLNet_GetError() );
            return false;
        }

        INFO( "Host %#08x", udp_address.host );

        //udp_address.host = INADDR_BROADCAST;

        ret = SDLNet_UDP_Bind( lan_announce_socket, -1, &udp_address );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_UDP_Bind: %s", SDLNet_GetError() );
            return false;
        }
        else
        {
            INFO( "Bound channel %d", ret );
            announce_channel = ret;
        }

        ret = SDLNet_UDP_Bind( lan_announce_socket, -1, &internet_udp_address );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_UDP_Bind: %s", SDLNet_GetError() );
            return false;
        }
        else
        {
            INFO( "Bound channel %d", ret );
            internet_announce_channel = ret;
        }

        started = true;
        INFO( "Server anouncer started" );

        json_cache = "[";
        json_cache += ServerEntry::GetJSON( local_server_params );
        json_cache += "]";

        return true;
    }

    void ServerAdvertisement::Stop()
    {
        if ( !started )
        {
            return;
        }
        started = false;
        if ( lan_announce_socket )
        {
            SDLNet_UDP_Close( lan_announce_socket );
            lan_announce_socket = NULL;
        }
        local_server_params.clear();
    }

    void * ServerAdvertisement::HTTPAnnounce( void * context )
    {
        //ServerAdvertisement * sa = (ServerAdvertisement*)context;
        char * post = ( char* )context;
        IPaddress ip;
        int ret;
        const char * master_list_server_address = IMSL_ADDRESS;
        const char * master_server_http_file = IMSL_ANNOUNCE_SERVER_PATH;
        uint16_t port = 80;
        uint8_t server_list_buffer[64*1024] = {};
        size_t buffer_size = 64*1024;
        TCPsocket server_list_socket = NULL;
        int post_size = 0;
        size_t offset;

        CHECK( post,NULL );

        ret = SDLNet_ResolveHost( &ip,
                master_list_server_address,
                port );
        if ( ret==-1 )
        {
            FAILURE( "SDLNet_ResolveHost: %s", SDLNet_GetError() );
            goto end;
        }

        server_list_socket = SDLNet_TCP_Open( &ip );
        if ( !server_list_socket )
        {
            FAILURE( "SDLNet_TCP_Open: %s", SDLNet_GetError() );
            goto end;
        }

        snprintf(( char* )server_list_buffer,
                buffer_size,
                "POST %s HTTP/1.1" HTTP_LF
                "Host: %s" HTTP_LF
                "Content-Type: application/x-www-form-urlencoded" HTTP_LF
                "Content-Length: " SIZE_T_FORMAT HTTP_LF
                "Accept: text/html" HTTP_LF
                HTTP_LF
                "%s%n",
                master_server_http_file,
                master_list_server_address,
                strlen( post ),
                post,
                &post_size );
        //INFO("%.*s", post_size, server_list_buffer);
        SDLNet_TCP_Send( server_list_socket, server_list_buffer, post_size );

        offset = 0;
        do
        {

            ret = SDLNet_TCP_Recv( server_list_socket, &server_list_buffer[offset], buffer_size );
            if ( ret > 0 ) offset += ret;
        }
        while ( ret > 0 );

        if ( strncmp(( char* )server_list_buffer, "HTTP/1.1 200 OK", std::min( strlen( "HTTP/1.1 200 OK" ), offset ) ) != 0 )
        {
            FAILURE( "%.*s", ( int )offset, server_list_buffer );
        }
        else
        {
            const char * status_ok = HTTP_LF HTTP_LF "ok";
            if ( memmem( server_list_buffer, offset, status_ok, strlen( status_ok ) ) == NULL )
            {
                WARNING( "%.*s", ( int )offset, server_list_buffer );
            }
            else
            {
                //INFO("%.*s", (int)offset, server_list_buffer);
            }
        }

        SDLNet_TCP_Close( server_list_socket );

end:
        free( post );

        return NULL;
    }

    void http_encode( std::string & url )
    {
        do
        {
            size_t pos = url.find( ' ', 0 );
            if ( pos == url.npos ) break;
            url.replace( pos, 1, "+" );

        }
        while ( 1 );
    }

    void ServerAdvertisement::Update()
    {
        if ( !started )
            return;

        time_t now = time( NULL );

        if ( last_announce + ANNOUNCE_RATE <= now )
        {
            last_announce = now;
            UDPpacket * packet = GetPacket();
            if ( packet )
            {
                std::string header_string = EASY_SERVER_MAGIC + game_name_magic + ":" + json_cache;
                size_t header_length = header_string.length();
                memcpy( packet->data, header_string.c_str(), header_length );
                packet->len = header_length;

                SDLNet_UDP_Send( lan_announce_socket, announce_channel, packet );

                ReturnPacket( packet );
            }
        }
        if ( announce_internet
                && last_internet_announce + ServerAdvertisement::INTERNET_ANNOUNCE_RATE <= now )
        {
            last_internet_announce = now;

            //INFO("Internet Announce");
            if ( use_http )
            {
                std::string post;
                std::string json_cache_encoded = json_cache;
                http_encode( json_cache_encoded );
                post += "game=";
                post += game_name_magic.c_str();
                post += "&json=";

                post += json_cache_encoded;

                pthread_create_detached( ServerAdvertisement::HTTPAnnounce, strdup( post.c_str() ) );
            }
            else
            {
                std::string header_string = EASY_SERVER_MAGIC + game_name_magic + ":" + json_cache;
                //INFO("%s", header_string.c_str());
                UDPpacket * packet = GetPacket();

                if ( packet )
                {
                    size_t header_length = header_string.length();
                    memcpy( packet->data, header_string.c_str(), header_length );
                    packet->len = header_length;

                    SDLNet_UDP_Send( lan_announce_socket, internet_announce_channel, packet );
                    ReturnPacket( packet );
                }
            }
        }
    }

    UDPpacket * ServerAdvertisement::GetPacket()
    {
        return SDLNet_AllocPacket( 1024 );
    }

    void ServerAdvertisement::ReturnPacket( UDPpacket * packet )
    {
        CHECK( packet, );
        SDLNet_FreePacket( packet );
    }

    InternetMasterServer::InternetMasterServer() :
            internet_collect_socket( NULL ),
            server_list_accept_socket( NULL ),
            socket_set( NULL ),
            game_server_list_map(),
            game_name_magic()
    {

    }

    bool InternetMasterServer::Start(
        std::string game_name_magic )
    {
        int ret = 0;
        IPaddress ip;

        this->game_name_magic = game_name_magic;

        ret = SDLNet_Init();
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_Init: %s",SDLNet_GetError() );
            return false;
        }

        socket_set=SDLNet_AllocSocketSet( 16 );
        if ( !socket_set )
        {
            FAILURE( "SDLNet_AllocSocketSet: %s", SDLNet_GetError() );
            return false;
        }

        ret = SDLNet_ResolveHost( &ip,NULL,INTERNET_MASTER_SERVER_LIST_PORT );
        if ( ret==-1 )
        {
            FAILURE( "SDLNet_ResolveHost: %s", SDLNet_GetError() );
            return false;
        }

        //UDP
        internet_collect_socket = SDLNet_UDP_Open( INTERNET_MASTER_SERVER_REGISTER_PORT );
        if ( !internet_collect_socket )
        {
            FAILURE( "SDLNet_UDP_Open: %s", SDLNet_GetError() );
            return false;
        }

        ret = SDLNet_UDP_AddSocket( socket_set, internet_collect_socket );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_UDP_AddSocket: %s", SDLNet_GetError() );
            return false;
        }

        //TCP
        server_list_accept_socket = SDLNet_TCP_Open( &ip );
        if ( !server_list_accept_socket )
        {
            FAILURE( "SDLNet_TCP_Open: %s", SDLNet_GetError() );
            perror( "SDLNet_TCP_Open" );
            return false;
        }

        ret = SDLNet_TCP_AddSocket( socket_set, server_list_accept_socket );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_TCP_AddSocket: %s", SDLNet_GetError() );
            return false;
        }

        while ( 1 )
        {
            Update();
        }

        return true;
    }

    UDPpacket * InternetMasterServer::GetPacket()
    {
        return SDLNet_AllocPacket( 1024 );
    }

    void InternetMasterServer::ReturnPacket( UDPpacket * packet )
    {
        CHECK( packet, );
        SDLNet_FreePacket( packet );
    }

    static bool safe_char( char c )
    {
        if (( c >= '0' && c <= '9' )
                || ( c >= 'A' && c <= 'Z' )
                || ( c >= 'a' && c <= 'z' )
                || ( c == ' ' ) )
        {
            return true;
        }
        return false;
    }

    void InternetMasterServer::TryReceiveAnnouncement( UDPpacket * packet )
    {
        CHECK( packet, );

        uint8_t * buffer = packet->data;
        uint32_t length = packet->len;

        if ( length < EASY_SERVER_MAGIC_LENGTH )
        {
            FAILURE( "Bad magic" );
            return;
        }

        if ( memcmp(
                    buffer,
                    EASY_SERVER_MAGIC,
                    EASY_SERVER_MAGIC_LENGTH ) != 0 )
        {
            FAILURE( "Bad magic" );
            return;
        }

        buffer += EASY_SERVER_MAGIC_LENGTH;
        length -= EASY_SERVER_MAGIC_LENGTH;

        uint8_t * offset = ( uint8_t * )memchr( buffer, ':', length );
        if ( !offset )
        {
            FAILURE( "Bad game name" );
        }

        size_t game_name_len = offset - buffer;
        size_t naughty_offset = 0;
        for ( ; naughty_offset < game_name_len; naughty_offset++ )
        {
            if ( !safe_char( buffer[naughty_offset] ) )
            {
                FAILURE( "Naughty game name" );
                return;
            }
        }

        std::string game_name = std::string(( char* )buffer, game_name_len );

        if ( game_name_magic.length() != 0 )
        {
            if ( game_name_magic != game_name )
            {
                FAILURE( "Game name didn't match filter" );
                return;
            }
        }

        //INFO("Announce for \"%s\"", game_name.c_str());

        buffer += game_name_len;
        length -= game_name_len;

        if ( length <= 1 )
        {
            FAILURE( "Unable to find json" );
            return;
        }
        buffer += 1;
        length -= 1;

        //ServerBrowser::server_entry_map_t new_sem = ServerBrowser::ParseServerList(buffer, length);
        std::list<ServerEntry*> se_list;
        bool parsed = parse_server_list( se_list, buffer, length );
        if ( !parsed )
        {
            FAILURE( "Parsing error" );
            return;
        }

        if ( se_list.size() != 1 )
        {
            FAILURE( "Didn't parse 1 server" );
            return;
        }

        game_server_list_map_t::iterator game_itr = game_server_list_map.find( game_name );

        ServerBrowser::server_entry_map_t * sem = NULL;

        if ( game_itr == game_server_list_map.end() )
        {
            INFO( "Creating entry for game \"%s\"", game_name.c_str() );
            sem = new ServerBrowser::server_entry_map_t();
            game_server_list_map[game_name] = sem;
        }
        else
        {
            sem = game_server_list_map[game_name];
        }

        std::list<ServerEntry*>::iterator itr = se_list.begin();

        //only process the first
        for ( ; itr == se_list.begin() && itr != se_list.end(); itr++ )
        {
            ServerEntry * se = *itr;


            char temp[32]; //strlen("255.255.255.255:65536")
            uint8_t ip[4] =
            {
                packet->address.host & 0xff,
                ( packet->address.host >> 8 ) & 0xff,
                ( packet->address.host >> 16 ) & 0xff,
                ( packet->address.host >> 24 ) & 0xff,
            };
            uint16_t port = SDLNet_Read16( &packet->address.port );
            snprintf( temp,32,"%d.%d.%d.%d:%d",
                    ip[0],ip[1],ip[2],ip[3],
                    port );

            std::string key = temp;
            {
                snprintf( temp,32,"%d.%d.%d.%d",
                        ip[0],ip[1],ip[2],ip[3] );
                se->Add( "address", temp );
                //snprintf(temp,32,"%d",
                //    port);
                //se->Add("port", temp);

                time_t now = time( NULL );

                se->Add( "refresh", now );
            }

            ServerBrowser::server_entry_map_t::iterator se_itr = sem->find( key );
            if ( se_itr != sem->end() )
            {
                //INFO("Updating entry");
                ServerEntry * old = se_itr->second;
                delete( old );
                se_itr->second = NULL;
                old = NULL;
            }
            else
            {
                INFO( "Adding new entry" );
            }
            ( *sem )[key] = se;
            //Make sure this se doesn't get wacked
            *itr = NULL;
        }



    }

    void InternetMasterServer::HandleAcceptedSocket( TCPsocket client_tcp_socket )
    {
        CHECK( client_tcp_socket, );

        std::string json = GetJSON( *game_server_list_map["tanktank"] );
        //INFO("\"%s\"", json.c_str());

        //TODO Wildly blocky

        SDLNet_TCP_Send( client_tcp_socket, json.c_str(), json.length() );

        SDLNet_TCP_Close( client_tcp_socket );
    }

    void InternetMasterServer::Update()
    {
        int ret = 0;

        ret = SDLNet_CheckSockets( socket_set, 1000 );
        if ( ret == -1 )
        {
            FAILURE( "SDLNet_CheckSockets: %s", SDLNet_GetError() );
            return;
        }

        Purge();

        if ( ret > 0 )
        {
            if ( SDLNet_SocketReady( internet_collect_socket ) )
            {
                UDPpacket * packet = GetPacket();
                if ( packet )
                {
                    ret = SDLNet_UDP_Recv( internet_collect_socket, packet );
                    if ( ret == -1 )
                    {
                        FAILURE( "SDLNet_UDP_Recv: %s", SDLNet_GetError() );
                    }
                    else if ( ret )
                    {
                        TryReceiveAnnouncement( packet );
                    }
                    ReturnPacket( packet );
                }
            }
            if ( SDLNet_SocketReady( server_list_accept_socket ) )
            {

                TCPsocket client_tcp_socket = SDLNet_TCP_Accept( server_list_accept_socket );

                HandleAcceptedSocket( client_tcp_socket );
            }
        }
    }

    std::string InternetMasterServer::GetJSON( const ServerBrowser::server_entry_map_t & map )
    {
        std::string json = "[";

        ServerBrowser::server_entry_map_t::const_iterator itr = map.begin();

        bool first = true;
        for ( ; itr != map.end(); itr++ )
        {
            if ( first )
            {
                first = false;
            }
            else
            {
                json += ",";
            }
            ServerEntry * se = itr->second;
            json += ServerEntry::GetJSON( se->GetParams() );
        }

        json += "]";

        return json;
    }

    void InternetMasterServer::Purge()
    {
        game_server_list_map_t::iterator gslm_itr = game_server_list_map.begin();
        for ( ; gslm_itr != game_server_list_map.end(); gslm_itr++ )
        {
            ServerBrowser::server_entry_map_t * sem = gslm_itr->second;
            ServerBrowser::server_entry_map_t::iterator sem_itr = sem->begin();

            std::vector<std::string> remove;

            time_t now = time( NULL );

            for ( ; sem_itr != sem->end(); sem_itr++ )
            {
                ServerEntry * se = sem_itr->second;
                int refresh_time = 0;
                bool got_refresh = se->GetField( "refresh", refresh_time );


                if ( !got_refresh
                        || ( now > refresh_time + InternetMasterServer::INTERNET_MASTER_SERVER_REFRESH_LIMIT ) )
                {
                    INFO( "Purging \"%s\"", sem_itr->first.c_str() );
                    remove.push_back( sem_itr->first );
                }
            }

            std::vector<std::string>::iterator remove_itr = remove.begin();
            for ( ; remove_itr != remove.end(); remove_itr++ )
            {
                ServerBrowser::server_entry_map_t::iterator sem_itr = sem->find( *remove_itr );
                delete( sem_itr->second );
                sem->erase( sem_itr );
            }
        }


    }
}










