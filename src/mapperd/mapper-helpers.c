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

#include <mapper.h>

static uint32_t nr_reqs = 0;
static uint32_t waiters_for_req = 0;
st_cond_t req_cond;
char buf[XSEG_MAX_TARGETLEN + 1];

static char * get_cas_name(struct map *map, uint64_t idx)
{
    if (map->cas_array == NULL || idx >= map->cas_nr) {
        return NULL;
    }

    return map->cas_array[idx];
}

static struct vol_idx * get_vol_name(struct map *map, uint64_t idx)
{
    if (idx == 0) {
        return map->volume;
    }

    if (map->vol_array == NULL || idx >= map->vol_nr) {
        return NULL;
    }

    return map->vol_array[idx];
}

int get_object_name(char *object, uint32_t object_len, struct map *map,
                        uint64_t idx)
{
    struct mapping *m;

    if (idx >= map->nr_objs) {
        return -EINVAL;
    }

    m = map->objects[idx];

    if (m->flags & MF_OBJECT_ZERO) {
        // zero objects should not have names
        // do not call this if object is zero;
        return -EINVAL;
    } else if (m->flags & MF_OBJECT_ARCHIP) {
        int r;
        uint64_t be_epoch = __cpu_to_be64(m->vol_epoch)
        uint64_t be_index = __cpu_to_be64(idx)
        char hexlified_index[HEXLIFIED_INDEX_LEN + 1];
        char hexlified_epoch[HEXLIFIED_EPOCH_LEN + 1];
        char *vol_name;
        struct vol_idx *vi;

        vi = get_vol_name(map, m->name_idx);
        if (!vi) {
            return -EINVAL;
        }

        hexlify((unsigned char *)&be_index, sizeof(be_index), hexlified_index);
        hexlified_epoch[HEXLIFIED_EPOCH_LEN] = '\0';
        hexlify((unsigned char *)&be_epoch, sizeof(be_epoch), hexlified_epoch);
        hexlified_index[HEXLIFIED_INDEX_LEN] = '\0';

        r = snprintf(object, object_len, "%.*s_%s_%s",
                     vi->len, vi->name, hexlified_epoch, hexlified_idx);
        if (r < 0) {
            return r;
        } else if (r >= object_len) {
            return -ERANGE;
        }

        return 0;
    } else {
        // CAS object
        char *cas_object;

        cas_object = get_cas_name(map, m->name_idx);
        if (!cas_object) {
            return -EINVAL;
        }

        if (object_len < map->cas_size + 1) {
            return -ERANGE;
        }

        memcpy(object, cas_object, map->cas_size);
        object[map->cas_size] = '\0';

        return 0;
    }
}
