#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <rados/librados.h>
#include "api_types.h"

/* API implementation-specific */
#define MAX_CR_OBJECT_NAME 100

static rados_ioctx_t ioctx;

// ---- Utils ----
void create_cr_object_name(char *buf, size_t n, uuid_t id) {
    snprintf(buf, n, "cr_object_%d", id);
}

int is_registered(uuid_t client_id) {
    char cr_obj[MAX_CR_OBJECT_NAME];

    create_cr_object_name(cr_obj, MAX_CR_OBJECT_NAME, client_id);

    if (rados_stat(ioctx, cr_obj, NULL, NULL) == -ENOENT) {
	return 0;
    } else {
	return 1;
    }
}
// ---------------

/* TYPES */

struct conf_registry_state {
    uuid_t client_id;               /* unique identifier for client */
    client_status_t client_status;  /* status of the membership of the client */
    endpoint_t client_config_endpoint; /* API endpoint for the configuration API
					  of the client */
    info_t client_info;             /* client-side information that properly
				       identify the client and its purpose to
				       the administrator or the developer
				       inspecting the registry */
    config_t client_config;         /* information and state that an application
				       requires to be present in the client
				       context, such as credentials, or session
				       data */
};

/* FUNCTIONS */

/*
  Registers a client with a unique id.

  If the client_id is already registered, the call fails.

  Requires an EXCLUSIVE lock on 'clients' in the registry.
 */
int register_client(uuid_t client_id, endpoint_t client_config_endpoint,
		    info_t client_info) {
    char cr_obj[MAX_CR_OBJECT_NAME];
    struct conf_registry_state *state = malloc(sizeof(struct conf_registry_state));

    if (!is_registered(client_id)) {
	state->client_id = client_id;
	state->client_status = ACTIVE;
	state->client_config_endpoint = client_config_endpoint;
	state->client_info = client_info;
	state->client_config = "";

	create_cr_object_name(cr_obj, MAX_CR_OBJECT_NAME, client_id);

	if (rados_write_full(ioctx, cr_obj, (char *) state,
			     sizeof(struct conf_registry_state)) < 0) {
	    fprintf(stderr, "register_client: cannot write to pool!\n");
	    return -1;
	}
    } else {
	printf("Registering client %d failed! Client exists.\n", client_id);
	return -1;
    }

    return 0;
}

/*
  Set the client_status.

  The caller is trusted to report a status that corresponds to the real state of
  the system. The registry does not have the means to maintain any state by
  itself. It is expected that appropriate agents will monitor the system and
  registry and report any status changes to the registry, and apply any
  configuration changes to the system.

  Requires a CONCURRENT WRITE lock on 'clients' and an EXCLUSIVE lock on
  client_id.
 */
int set_client_status(uuid_t client_id, client_status_t status) {
    char cr_obj[MAX_CR_OBJECT_NAME];

    create_cr_object_name(cr_obj, MAX_CR_OBJECT_NAME, client_id);

    // XXX: Would it be better to write full conf_registry_state?
    if (rados_write(ioctx, cr_obj, (char *) &status, sizeof(client_status_t),
		    sizeof(uuid_t)) < 0) {
	fprintf(stderr, "set_client_status: cannot write status to pool!\n");
	return -1;
    }

    return 0;
}

/*
  Return client_status, client_config_endpoint, and client_info for the client
  identified by client_id in the registry.

  Requires a CONCURRENT READ lock on 'clients' and a CONCURRENT READ lock on
  client_id.
 */
int get_client_info(uuid_t client_id, info_t *client_info) {
    char cr_obj[MAX_CR_OBJECT_NAME];
    int info_offset = sizeof(uuid_t) + sizeof(client_status_t) + sizeof(endpoint_t);

    create_cr_object_name(cr_obj, MAX_CR_OBJECT_NAME, client_id);

    if (rados_read(ioctx, cr_obj, (char *) client_info, sizeof(info_t),
		   info_offset) < 0) {
	fprintf(stderr, "get_client_info: cannot get info from pool!\n");
	return -1;
    }

    return 0;
}

/*
  Return the client_config for the identified client.

  This can be used for administrative inspection, or by the clients themselves
  upon recovery, to re-initialize themselves.

  Requires a CONCURRENT READ lock on 'clients' and a CONCURRENT READ lock on
  client_id.
 */
int get_client_config(uuid_t client_id, config_t *client_config) {
    char cr_obj[MAX_CR_OBJECT_NAME];
    int config_offset = sizeof(uuid_t) + sizeof(client_status_t) + sizeof(endpoint_t) +
	sizeof(info_t);

    create_cr_object_name(cr_obj, MAX_CR_OBJECT_NAME, client_id);

    if (rados_read(ioctx, cr_obj, (char *) client_config, sizeof(config_t),
		   config_offset) < 0) {
	fprintf(stderr, "get_client_config: cannot get config from pool!\n");
	return -1;
    }

    return 0;
}

/*
  Set the client_config for the identified client.

  This is used to configure a client, either called by the client itself to
  register its configuration, or by another entity providing configuration for
  the client.

  Requires a CONCURRENT WRITE lock on 'clients' and an EXCLUSIVE lock on
  client_id.
 */
int set_client_config(uuid_t client_id, config_t config) {
    int config_offset = sizeof(uuid_t) + sizeof(client_status_t) + sizeof(endpoint_t) +
	sizeof(info_t);
    char cr_obj[MAX_CR_OBJECT_NAME];

    create_cr_object_name(cr_obj, MAX_CR_OBJECT_NAME, client_id);

    // XXX: Would it be better to write full conf_registry_state?
    if (rados_write(ioctx, cr_obj, (char *) &config, sizeof(config_t),
		    config_offset) < 0) {
	fprintf(stderr, "set_client_config: cannot write config to pool!\n");
	return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    rados_t cluster;
    const char *poolname = "test_trololo";
    
    // Connect to cluster
    if (rados_create(&cluster, NULL) < 0) {
	fprintf(stderr, "%s: cannot create a cluster handle.\n", argv[0]);
	return -1;
    }

    if (rados_conf_read_file(cluster, "/etc/ceph/ceph.conf") < 0) {
	fprintf(stderr, "%s: cannot read config file.\n", argv[0]);
	return -1;
    }

    if (rados_connect(cluster) < 0) {
	fprintf(stderr, "%s: cannot connect to cluster.\n", argv[0]);
	return -1;
    }

    if (rados_ioctx_create(cluster, poolname, &ioctx) < 0) {
	fprintf(stderr, "%s: cannot open rados pool: %s.\n", argv[0], poolname);
	return -1;
    }

    info_t client;
    if (register_client(1, "127.0.0.1", "My test config") < 0) {
        goto cleanup;
    }

    // Test various api calls
    set_client_status(1, FENCING);
    get_client_info(1, &client);
    printf("Info: %s\n", client);

    config_t config;
    get_client_config(1, &config);
    printf("Old config: %s\n", config);
    set_client_config(1, "nonsense!");
    get_client_config(1, &config);
    printf("New config: %s\n", config);

cleanup:
    // Clean-up
    rados_ioctx_destroy(ioctx);
    rados_shutdown(cluster);

    return 0;
}
