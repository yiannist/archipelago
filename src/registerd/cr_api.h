int init();
int finalize();
int register_client(int client_id, char *client_config_endpoint, char *client_info);
int set_client_status(int client_id, client_status_t client_status);
int get_client_info(int client_id);
int get_client_config(int client_id);
int set_client_config(int client_id, char *client_config);
