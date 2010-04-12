/* 
 * File:   Util.h
 * Author: afaucher
 *
 * Created on May 30, 2009, 3:03 PM
 */

#ifndef _LIBTANKFIND_UTIL_H
#define	_LIBTANKFIND_UTIL_H

#include <assert.h>
#include <vector>

#define NORMAL "\033[0m"

#define RED "\033[0;31m"
#define YELLOW "\033[0;33m"
#define GREEN "\033[0;32m"

#define BLUE "\033[0;34m"
#define CYAN "\033[0;36m"
#define MAGENTA "\033[0;35m"
#define WHITE "\033[0;37m"
#define LIGHT_GREEN "\033[0;92m"
#define LIGHT_YELLOW "\033[0;93m"
#define LIGHT_BLUE "\033[0;94m"
#define LIGHT_RED "\033[0;91m"
#define LIGHT_PURPLE "\033[0;95m"

#define BOLD "\033[1m"
#define ITALICS "\033[3m"

#define TRACE(fmt, args...) printf( LIGHT_BLUE "%s:%s:%d " NORMAL fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#define INFO(fmt, args...) printf( BLUE "%s:%s:%d " NORMAL fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#define WARNING(fmt, args...) printf( YELLOW "WARNING %s:%s:%d " NORMAL fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#define FAILURE(fmt, args...) printf( RED "FAILURE %s:%s:%d " NORMAL fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##args)

#define CHECK(condition, ret) { \
    bool _check = (condition); \
    if (!_check) { \
        FAILURE("Failed check " #condition); \
        return ret; \
    } \
}

#ifdef WIN32
#define SIZE_T_FORMAT "%u"
#else
#define SIZE_T_FORMAT "%Zd"
#endif

#endif	/* _LIBTANKFIND_UTIL_H */

