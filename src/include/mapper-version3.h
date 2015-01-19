/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MAPPERVERSION3_H

#define MAPPERVERSION3_H

#include <unistd.h>
#include <hash.h>
#include <peer.h>

struct map;

/* Maximum length of an object name in memory */
#define v3_max_objectlen 123

/* Required size in storage to store object information.
 *
 * byte for flags + mapping->objectlen + max object len in disk
 */
struct v3_object_on_disk {
    unsigned char flags;
    uint32_t objectlen;
    unsigned char object[v3_max_objectlen];
} __attribute__ ((packed));

//This must be a power of 2. Currently set to 128.
#define v3_objectsize_in_map (sizeof(struct v3_object_on_disk))

/* Map header contains:
 * 	map signature - uint32_t
 * 	map version   - uint32_t
 * 	volume size   - uint64_t
 * 	block size    - uint32_t
 * 	map flags     - uint32_t
 * 	map epoch     - uint64_t
 */
struct v3_header_struct {
    uint32_t signature;
    uint32_t version;
    uint64_t size;
    uint32_t blocksize;
    uint32_t flags;
    uint64_t epoch;
} __attribute__ ((packed));

#define v3_mapheader_size (sizeof(struct v3_header_struct))

extern struct map_ops v3_ops;

int read_map_header_v3(struct map *map, struct v3_header_struct *v3_hdr);
void write_map_header_v3(struct map *map, struct v3_header_struct *v3_hdr);

#endif                          /* end MAPPERVERSION3_H */
