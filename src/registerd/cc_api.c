#include <stdio.h>
#include "api_types.h"

/* TYPES */

struct client_configuration_state {
    endpoint_t registry_endpoint;    /* The endpoint of the registry it is
					connected to */
    info_t client_info;
    client_status_t client_status;
    config_t client_config;
};


/* FUNCTIONS */

/*
  Acquire a long term lock.

  The lock will not be acquired and released for each access. If release is
  required it must be requested through configuration (via release_longterm()).

  If writeable is true, then the client tries to acquire a PROTECTED WRITE lock
  for the named lock. If writeable is false, then the client tries to acquire a
  CONCURRENT READ lock.

  The caching mode is set from the corresponding argument. The caching mode can
  be either EXCLUSIVE or SHARED, explained previously.

  A second call for the same map can upgrade or downgrade writeable, or set a
  new caching mode.
 */
int acquire_longterm(char *lock_name, writeable_t writeable,
		     caching_mode_t caching_mode) {
    printf("Locking: %s with (writeable, caching) mode: (%d, %d).\n", lock_name,
	   writeable, caching_mode);

    return 0;
}

/*
  Complete or abort any pending access related with the lock and releases it.

  Note that upon releasing the long term lock the client does not lose the
  ability to access a resource. It falls back to acquiring and releasing a lock
  for each access.
 */
int release_longterm(char *lock_name) {
    printf("Unlocking longterm: %s.\n", lock_name);

    return 0;
}

/*
  If the call is successful, the client will immediately prevent itself from any
  future access to any resource. This is to request a graceful shutdown of
  clients for fencing them. Nevertheless, the caller should be able to fence the
  client without its cooperation if needed.
 */
int kill() {
    printf("Commiting suicide\n");

    return 0;
}
