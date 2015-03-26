#ifndef CC_API_H
#define CC_API_H

int acquire_longterm(char *lock_name, writeable_t writeable, caching_mode_t caching_mode);
int release_longterm(char *lock_name);
int kill();
#endif /* CC_API_H */
