import os

env = Environment()

env.ParseConfig('pkg-config --libs --cflags sigc++-2.0')
env.ParseConfig('pkg-config --libs --cflags sdl')

sources = Split('''
    ServerBrowser.cc
    json/JSON_parser.c
    ''')
env.Library('easyserverbrowser', sources)

libs = Split('''
    easyserverbrowser
    pthread
    SDL_net
    ''')
env.Append(LIBS=libs)
    
lib_path = Split('''
	./
	''')
env.Append(LIBPATH=lib_path)

include_path = Split('''
    ./
    ''')
env.Append(CPPPATH=include_path)

env.Program('ims', 'test/InternetMasterServer.cc')
env.Program('announce', 'test/ServerAnnounce.cc')
env.Program('browse', 'test/ServerBrowse.cc')
