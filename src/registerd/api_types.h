#ifndef API_TYPES_H
#define API_TYPES_H

typedef int   uuid_t;
typedef char* endpoint_t;
typedef char* info_t;
typedef char* config_t;

typedef enum {
    ACTIVE,         /* client is alive and functioning */
    UNAVAILABLE,    /* client is not reachable */
    FENCING,        /* client is excluded from access to Objects and
                       ObjectMaps */
    DISABLED        /* client is considered completely inactive */
} client_status_t;

typedef enum {PROTECTED_WRITE, PROTECTED_READ,
	      CONCCONCURRENT_WRITE, CONCURRENT_READ} writeable_t;
typedef enum {EXCLUSIVE, SHARED} caching_mode_t;

#endif /* API_TYPES_H */
