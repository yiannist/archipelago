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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>
#include <xseg/xhash.h>
#include <asm/byteorder.h>

#include "peer.h"
#include "hash.h"
#include "mapper.h"
#include "mapper-versions.h"
#include "mapper-helpers.h"


#define NO_V0SIZE ((uint64_t)-1)

int set_req_ctx(struct mapper_io *mio, struct xseg_request *req,
                struct req_ctx *rctx)
{
    XSEGLOG2(&lc, D, "Inserting ctx %lx of request %lx on mio %lx",
                 rctx, req, mio);

    g_hash_table_insert(mio->req_ctxs, req, rctx);

    XSEGLOG2(&lc, D, "Inserted ctx %lx of request %lx on mio %lx",
                 rctx, req, mio);
    return 0;
}

int remove_req_ctx(struct mapper_io *mio, struct xseg_request *req)
{
    gboolean ret;

    XSEGLOG2(&lc, D, "Removing ctx of request %lx from mio %lx", req, mio);

    ret = g_hash_table_remove(mio->req_ctxs, req);
    if (!ret) {
        XSEGLOG2(&lc, E, "Deleting ctx of request %lx on mio %lx failed",
                 req, mio);
        return -ENOENT;
    }

    XSEGLOG2(&lc, D, "Removed ctx of request %lx from mio %lx", req, mio);

    return 0;
}

struct req_ctx * get_req_ctx(struct mapper_io *mio, struct xseg_request *req)
{
    struct req_ctx *ret;

    ret = g_hash_table_lookup(mio->req_ctxs, req);
    if (ret == NULL) {
        XSEGLOG2(&lc, W, "Cannot find ctx of req %lx on mio %lx", req, mio);
        return NULL;
    }

    XSEGLOG2(&lc, D, "Found ctx %lx of req %lx on mio %lx", ret, req, mio);

    return ret;
}

int __set_node(struct mapper_io *mio, struct xseg_request *req,
               struct mapping *mn)
{
    int r = 0;
    if (mn) {
        XSEGLOG2(&lc, D, "Inserting (req: %lx, mapnode: %lx) on mio %lx",
                 req, mn, mio);
        r = xhash_insert(mio->copyups_nodes, (xhashidx) req, (xhashidx) mn);
        if (r == -XHASH_ERESIZE) {
            xhashidx shift = xhash_grow_size_shift(mio->copyups_nodes);
            xhash_t *new_hashmap =
                xhash_resize(mio->copyups_nodes, shift, 0, NULL);
            if (!new_hashmap) {
                return -1;
            }
            mio->copyups_nodes = new_hashmap;
            r = xhash_insert(mio->copyups_nodes, (xhashidx) req,
                             (xhashidx) mn);
        }
        if (r < 0) {
            XSEGLOG2(&lc, E, "Insertion of (%lx, %lx) on mio %lx failed",
                     req, mn, mio);
        }
    } else {
        XSEGLOG2(&lc, D, "Deleting req: %lx from mio %lx", req, mio);
        r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
        if (r == -XHASH_ERESIZE) {
            xhashidx shift = xhash_shrink_size_shift(mio->copyups_nodes);
            xhash_t *new_hashmap =
                xhash_resize(mio->copyups_nodes, shift, 0, NULL);
            if (!new_hashmap) {
                return -1;
            }
            mio->copyups_nodes = new_hashmap;
            r = xhash_delete(mio->copyups_nodes, (xhashidx) req);
        } else if (r == -XHASH_ENOENT) {
            XSEGLOG2(&lc, W, "%lx not found on mio %lx", req, mio);
            return -1;
        }
        if (r < 0) {
            XSEGLOG2(&lc, E, "Deletion of %lx on mio %lx failed", req, mio);
        }
    }
    return r;
}

struct mapping *__get_node(struct mapper_io *mio, struct xseg_request *req)
{
    struct mapping *mn;
    int r =
        xhash_lookup(mio->copyups_nodes, (xhashidx) req, (xhashidx *) & mn);
    if (r < 0) {
        XSEGLOG2(&lc, W, "Cannot find req %lx on mio %lx", req, mio);
        return NULL;
    }
    XSEGLOG2(&lc, D, "Found mapnode %lx req %lx on mio %lx", mn, req, mio);
    return mn;
}

struct xseg_request *__close_map(struct peer_req *pr, struct map *map)
{
    int r;
    struct peerd *peer = pr->peer;
    struct xseg_request *req;
    struct mapperd *mapper = __get_mapperd(peer);

    XSEGLOG2(&lc, I, "Closing map %s", map->volume);

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
        goto out_err;
    }

    req->op = X_RELEASE;
    req->size = 0;
    req->offset = 0;
    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 req, pr, map->volume);
        goto out_put;
    }


    XSEGLOG2(&lc, I, "Map %s closing", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int close_map(struct peer_req *pr, struct map *map)
{
    int err;
    struct xseg_request *req;

    map->state |= MF_MAP_CLOSING;
    req = __close_map(pr, map);
    if (!req) {
        map->state &= ~MF_MAP_CLOSING;
        return -1;
    }

    wait_on_pr(pr, (!((req->state & XS_FAILED) || (req->state & XS_SERVED))));
    map->state &= ~MF_MAP_CLOSING;
    err = req->state & XS_FAILED;
    put_request(pr, req);
    if (err) {
        return -1;
    } else {
        map->state &= ~MF_MAP_EXCLUSIVE;
    }
    return 0;
}

struct xseg_request *__open_map(struct peer_req *pr, struct map *map,
                                uint32_t flags)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);

    XSEGLOG2(&lc, I, "Opening map %s", map->volume);

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
        goto out_err;
    }

    req->op = X_ACQUIRE;
    req->size = MAPPER_DEFAULT_BLOCKSIZE;
    req->offset = 0;
    if (!(flags & MF_FORCE)) {
        req->flags = XF_NOSYNC;
    }

    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 req, pr, map->volume);
        goto out_put;
    }

    XSEGLOG2(&lc, I, "Map %s opening", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int open_map(struct peer_req *pr, struct map *map, uint32_t flags)
{
    int err;
    struct xseg_request *req;
    struct mapper_io *mio = __get_mapper_io(pr);

    map->state |= MF_MAP_OPENING;
    req = __open_map(pr, map, flags);
    if (!req) {
        map->state &= ~MF_MAP_OPENING;
        return -1;
    }
    wait_on_pr(pr, (!((req->state & XS_FAILED) || (req->state & XS_SERVED))));
    map->state &= ~MF_MAP_OPENING;
    err = req->state & XS_FAILED;
    put_request(pr, req);
    if (err) {
        return -1;
    } else {
        map->state |= MF_MAP_EXCLUSIVE;
        map->opened_count = mio->count;
    }
    return 0;
}

struct xseg_request *__write_map_metadata(struct peer_req *pr, struct map *map)
{
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct xseg_request *req;
    char *data;
    uint64_t pos;
    int r;
    struct header_struct hdr;
    uint32_t header_size = 0;


    switch (map->version) {
    case MAP_V0:
        write_map_header_v0(map, (struct v0_header_struct *) &hdr);
        header_size = v0_mapheader_size;
        break;
    case MAP_V1:
        write_map_header_v1(map, (struct v1_header_struct *) &hdr);
        header_size = v1_mapheader_size;
        break;
    case MAP_V2:
        write_map_header_v2(map, (struct v2_header_struct *) &hdr);
        header_size = v2_mapheader_size;
        break;
    case MAP_V3:
        write_map_header_v3(map, (struct v3_header_struct *) &hdr);
        header_size = v3_mapheader_size;
        break;
    default:
        XSEGLOG2(&lc, E, "Invalid version %u found", map->version);
        goto out_err;
    }
    if (!header_size) {
        goto out;
    }

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
                      header_size);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
        goto out_err;
    }


    req->op = X_WRITE;
    req->size = header_size;
    req->offset = 0;
    data = xseg_get_data(peer->xseg, req);
    memcpy(data, &hdr, header_size);

    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 req, pr, map->volume);
        goto out_put;
    }
  out:
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int write_map_metadata(struct peer_req *pr, struct map *map)
{
    int err;
    struct xseg_request *req;

    map->state |= MF_MAP_WRITING;
    req = __write_map_metadata(pr, map);
    if (!req) {
        map->state &= ~MF_MAP_WRITING;
        return -1;
    }
    wait_on_pr(pr, (!((req->state & XS_FAILED) || (req->state & XS_SERVED))));
    map->state &= ~MF_MAP_WRITING;
    err = req->state & XS_FAILED;
    put_request(pr, req);
    if (err) {
        return -1;
    }
    return 0;
}

/*
int write_map_data(struct peer_req *pr, struct map *map)
{
}
*/

int write_map(struct peer_req *pr, struct map *map)
{
    int r;
    map->state |= MF_MAP_WRITING;
    struct mapper_io *mio = __get_mapper_io(pr);

    mio->cb = NULL;
    mio->err = 0;

    r = map->mops->write_map_data(pr, map);
    if (r < 0) {
        map->state &= ~MF_MAP_WRITING;
        return r;
    }
    map->state &= ~MF_MAP_WRITING;

    return write_map_metadata(pr, map);
}


int delete_map_data(struct peer_req *pr, struct map *map)
{
    int r;
    map->state |= MF_MAP_DELETING_DATA;
    struct mapper_io *mio = __get_mapper_io(pr);

    XSEGLOG2(&lc, I, "Deleting map data for %s", map->volume);
    mio->cb = NULL;
    mio->err = 0;

    r = map->mops->delete_map_data(pr, map);

    map->state &= ~MF_MAP_DELETING_DATA;
    XSEGLOG2(&lc, I, "Deleted map data for %s", map->volume);
    return r;
}

struct xseg_request *__purge_map(struct peer_req *pr, struct map *map)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    uint64_t datalen;

    XSEGLOG2(&lc, I, "Purging map %s", map->volume);

    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen, 0);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
        goto out_err;
    }


    req->op = X_DELETE;
    req->size = 0;
    req->offset = 0;

    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 req, pr, map->volume);
        goto out_put;
    }

    XSEGLOG2(&lc, I, "Map %s purging ", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int purge_map(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;

    map->state |= MF_MAP_PURGING;

    r = delete_map(pr, map, 1);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Failed to purge map %s", map->volume);
        map->state &= ~MF_MAP_PURGING;
        return -1;
    }

    req = __purge_map(pr, map);
    if (!req) {
        goto out_err;
    }
    wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
    if (req->state & XS_FAILED) {
        goto out_put;
    }

    map->state &= ~MF_MAP_PURGING;
    put_request(pr, req);
    XSEGLOG2(&lc, I, "Purged map %s", map->volume);
    return 0;

  out_put:
    put_request(pr, req);
  out_err:
    XSEGLOG2(&lc, E, "Failed to purge map %s", map->volume);
    map->state &= ~MF_MAP_PURGING;
    return -1;
}

int delete_map(struct peer_req *pr, struct map *map, int delete_data)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);

    map->state |= MF_MAP_DELETING;

    mio->cb = NULL;
    mio->pending_reqs = 0;

    map->flags |= MF_MAP_DELETED;
    r = write_map_metadata(pr, map);
    if (r < 0) {
        map->flags &= ~MF_MAP_DELETED;
        map->state &= ~MF_MAP_DELETING;
        XSEGLOG2(&lc, E, "Failed to delete map %s", map->volume);
        return -1;
    }
    XSEGLOG2(&lc, I, "Deleted map %s", map->volume);

    if (delete_data) {
        r = delete_map_data(pr, map);
        if (r < 0) {
            //not fatal. Just log warning
            XSEGLOG2(&lc, E, "Delete map data failed for %s", map->volume);
        }
    }
    map->state &= ~MF_MAP_DELETING;
    return 0;
}

struct xseg_request *__load_map_metadata(struct peer_req *pr, struct map *map)
{
    int r;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    uint64_t datalen;

    XSEGLOG2(&lc, I, "Loading map metadata %s", map->volume);

    datalen = MAX_MAPHEADER_SIZE;
    req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
                      datalen);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
        goto out_err;
    }


    req->op = X_READ;
    req->size = datalen;
    req->offset = 0;

    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 req, pr, map->volume);
        goto out_put;
    }

    XSEGLOG2(&lc, I, "Map %s loading metadata", map->volume);
    return req;

  out_put:
    put_request(pr, req);
  out_err:
    return NULL;
}

int load_map_metadata(struct peer_req *pr, struct map *map)
{
    int type, r = 0;
    struct xseg_request *req;
    struct peerd *peer = pr->peer;
    char *data;
    uint32_t version;
    uint32_t signature;
    uint32_t assume_v0 = pr->req->flags & XF_ASSUMEV0;
    uint32_t signature_on_disk;
    uint32_t version1_on_disk;


    req = __load_map_metadata(pr, map);
    if (!req) {
        goto out_err;
    }
    wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
    if (req->state & XS_FAILED) {
        goto out_put;
    }
    if (req->serviced < req->size) {
        goto out_put;
    }

    data = xseg_get_data(peer->xseg, req);
    if (!data) {
        goto out_put;
    }

    signature_on_disk = __cpu_to_be32(MAP_SIGNATURE);
    version1_on_disk = __cpu_to_le32(MAP_V1);
    if (memcmp(data, &signature_on_disk, sizeof(MAP_SIGNATURE))) {
        if (assume_v0) {
            /* assume v0 */
            version = MAP_V0;
        } else if (!memcmp(data, &version1_on_disk, sizeof(uint32_t))) {
            version = MAP_V1;
        } else {
            XSEGLOG2(&lc, E, "No signature found");
            goto out_put;
        }
    } else {
        struct header_struct *hdr = (struct header_struct *) data;
        version = __be32_to_cpu(hdr->version);
    }

    switch (version) {
    case MAP_V0:
        r = read_map_header_v0(map, (struct v0_header_struct *) data);
        break;
    case MAP_V1:
        r = read_map_header_v1(map, (struct v1_header_struct *) data);
        break;
    case MAP_V2:
        r = read_map_header_v2(map, (struct v2_header_struct *) data);
        break;
    case MAP_V3:
        r = read_map_header_v3(map, (struct v3_header_struct *) data);
        break;
    default:
        XSEGLOG2(&lc, E, "Loaded invalid version %u > "
                 "latest version %u", version, MAP_LATEST_VERSION);
        goto out_put;
    }
    if (r < 0) {
        goto out_put;
    }

    put_request(pr, req);

    if (!is_valid_blocksize(map->blocksize)) {
        XSEGLOG2(&lc, E, "%s has Invalid blocksize %llu", map->volume,
                 map->blocksize);
        goto out_err;
    }

    return 0;

  out_put:
    put_request(pr, req);
  out_err:
    XSEGLOG2(&lc, E, "Load map version for map %s failed", map->volume);
    return -1;
}

int load_map(struct peer_req *pr, struct map *map)
{
    //struct xseg_request *req;
    int r;
    uint32_t prev_version;
    struct map_ops *prev_mops;
    uint64_t v0_size = NO_V0SIZE;
    uint64_t nr_objs = 0;

    XSEGLOG2(&lc, I, "Loading map %s", map->volume);

    map->state |= MF_MAP_LOADING;

    r = load_map_metadata(pr, map);
    if (r < 0) {
        goto out_err;
    }
    XSEGLOG2(&lc, D, "Loaded map metadata. Found map version %u",
             map->version);
    r = map->mops->load_map_data(pr, map);
    if (r < 0) {
        goto out_err;
    }

    v0_size = pr->req->v0_size;
    if (map->version == MAP_V0 && v0_size != NO_V0SIZE) {
        nr_objs = __calc_map_obj(v0_size, MAPPER_DEFAULT_BLOCKSIZE);
        if (map->nr_objs != nr_objs) {
            XSEGLOG2(&lc, E, "Size of v0 map invalid. "
                     "Read %llu objs vs %llu expected", map->nr_objs, nr_objs);
            goto out_err;
        } else {
            map->size = v0_size;
        }
    }

    if (map->version != MAP_LATEST_VERSION && (map->state & MF_MAP_EXCLUSIVE)) {
        /* update map to the latest version */
        /* FIXME assert that all old map data are overwritten */
        prev_version = map->version;
        prev_mops = map->mops;
        map->version = MAP_LATEST_VERSION;
        map->mops = MAP_LATEST_MOPS;
        if (write_map(pr, map) < 0) {
            XSEGLOG2(&lc, E, "Could not update map %s to latest version",
                     map->volume);
            map->version = prev_version;
            map->mops = prev_mops;
            goto out_err;
        }
    }

    map->state &= ~MF_MAP_LOADING;
    XSEGLOG2(&lc, I, "Loading map %s completed", map->volume);

    return 0;

  out_err:
    XSEGLOG2(&lc, E, "Loading of map %s failed", map->volume);
    map->state &= ~MF_MAP_LOADING;
    return -1;
}

static int copyup_copy_cb(struct peer_req *pr, struct xseg_request *req,
                            struct req_ctx *req_ctx)
{
    int r;
    struct peerd *peer = pr->peer;
    struct map *map;
    struct xseg_request *wreq;
    struct mapper_io *mio = __get_mapper_io(pr);

    req_ctx->orig_mapping->state &= ~MF_OBJECT_COPYING;

    map = req_ctx->map;
    //assert(map);
    if (!map) {
        return -1;
    }

    wreq = map->mops->prepare_write_object(pr, map, req_ctx->obj_idx, &req_ctx->copyup_mapping);
    if (!wreq) {
        XSEGLOG2(&lc, E,
                "Cannot prepare write object request for object %llu of map %s",
                (unsigned long long)req_ctx->obj_idx, map->volume);
        return -EIO;
    }

    r = set_req_ctx(mio, wreq, req_ctx);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot set request ctx");
        goto out_put;
    }

    r = send_request(pr, wreq);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 wreq, pr, map->volume);
        goto out_unset_ctx;
    }

    XSEGLOG2(&lc, I, "Writing object %llu of map: %s",
             (unsigned long long)req_ctx->obj_idx, map->volume);

    req_ctx->orig_mapping->state |= MF_OBJECT_WRITING;

    return 0;

out_unset_ctx:
    remove_req_ctx(mio, wreq);
out_put:
    put_request(pr, wreq);

    return -1;
}

static int copyup_write_cb(struct peer_req *pr, struct xseg_request *req,
                             struct req_ctx *req_ctx)
{
    //assert(req_ctx->orig_mapping)
    //assert(req_ctx->orig_mapping->state & MF_OBJECT_WRITING)

    // update mapping on cache
    req_ctx->orig_mapping->flags = req_ctx->copyup_mapping.flags;
    req_ctx->orig_mapping->vol_epoch = req_ctx->copyup_mapping.vol_epoch;
    req_ctx->orig_mapping->name_idx = req_ctx->copyup_mapping.name_idx;

    req_ctx->orig_mapping->state &= ~MF_OBJECT_WRITING;
    return 0;
}


void copyup_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct peerd *peer = pr->peer;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct req_ctx *req_ctx;
    struct mapping *m;

    req_ctx = get_req_ctx(mio, req);
    if (!req_ctx) {
        XSEGLOG2(&lc, E, "Cannot get request ctx");
        goto out_err;
    }

    remove_req_ctx(mio, req);

    m = req_ctx->orig_mapping;

    if (req->state & XS_FAILED) {
        XSEGLOG2(&lc, E, "Req failed");
        m->state &= ~MF_OBJECT_COPYING;
        m->state &= ~MF_OBJECT_WRITING;
        goto out_err;
    }

    if (req->op == X_WRITE) {
        if (copyup_write_cb(pr, req, req_ctx) < 0) {
            goto out_err;
        }
        XSEGLOG2(&lc, I, "Object write of %llu completed successfully",
                 req_ctx->obj_idx);

        mio->pending_reqs--;
        signal_mapnode(req_ctx->orig_mapping);
        free(req_ctx);
        signal_pr(pr);
    } else if (req->op == X_COPY) {
        if (copyup_copy_cb(pr, req, req_ctx) < 0) {
            goto out_err;
        }
        XSEGLOG2(&lc, I, "Object copy up completed. Pending writing.");
    } else {
        //wtf??
        ;
    }

out:
    put_request(pr, req);
    return;

out_err:
    mio->pending_reqs--;
    XSEGLOG2(&lc, D, "Mio->pending_reqs: %u", mio->pending_reqs);
    mio->err = 1;
    if (req_ctx->orig_mapping) {
        signal_mapnode(req_ctx->orig_mapping);
    }
    free(req_ctx);
    signal_pr(pr);
    goto out;
}

struct xseg_request *copyup_object(struct peer_req *pr, struct map *map,
                                   uint64_t obj_idx)
{
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct mapping copyup_mapping;
    struct xseg_request *req;
    struct xseg_request_copy *xcopy;
    struct req_ctx *req_ctx;
    uint32_t new_target_len = MAX_OBJECT_LEN + 1, orig_target_len = MAX_OBJECT_LEN + 1;
    char new_target[MAX_OBJECT_LEN + 1], orig_target[MAX_OBJECT_LEN + 1];
    int r = -1;


    if (obj_idx >= map->nr_objs) {
        return NULL;
    }

    req_ctx = calloc(1, sizeof(struct req_ctx));
    if (!req_ctx) {
        return NULL;
    }

    req_ctx->obj_idx = obj_idx;
    req_ctx->map = map;
    req_ctx->orig_mapping = &map->objects[obj_idx];
    req_ctx->copyup_mapping = map->objects[obj_idx];

    //assert(!(req_ctx->orig_mapping->flags & MF_OBJECT_WRITABLE));

    req_ctx->copyup_mapping.flags = MF_OBJECT_WRITABLE | MF_OBJECT_ARCHIP;
    req_ctx->copyup_mapping.name_idx = map->cur_vol_idx;
    req_ctx->copyup_mapping.vol_epoch = map->epoch;

    r = calculate_object_name(new_target, &new_target_len, map,
                              &req_ctx->copyup_mapping, obj_idx);
    if (r < 0) {
        goto out_err;
    }

    XSEGLOG2(&lc, D, "New target: %s (len: %d)", new_target, new_target_len);

    if (req_ctx->orig_mapping->flags & MF_OBJECT_ZERO) {
        XSEGLOG2(&lc, I, "Copy up of zero block is not needed. "
                         "Proceeding in writing the new object in map");

        req = map->mops->prepare_write_object(pr, map, obj_idx, &req_ctx->copyup_mapping);
        if (!req) {
            XSEGLOG2(&lc, E,
                    "Cannot prepare write object request for object %llu of map %s",
                    (unsigned long long)req_ctx->obj_idx, map->volume);
            goto out_err;
        }

        req_ctx->orig_mapping->state |= MF_OBJECT_WRITING;


    } else {
        r = calculate_object_name(orig_target, &orig_target_len, map,
                req_ctx->orig_mapping, obj_idx);
        if (r < 0) {
            goto out_err;
        }

        req = get_request(pr, mapper->bportno, new_target, new_target_len,
                sizeof(struct xseg_request_copy));

        xcopy = (struct xseg_request_copy *)xseg_get_data(peer->xseg, req);
        strncpy(xcopy->target, orig_target, orig_target_len);
        xcopy->targetlen = orig_target_len;

        req->offset = 0;
        req->size = map->blocksize;
        req->op = X_COPY;
    }

    r = set_req_ctx(mio, req, req_ctx);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot set request ctx");
        goto out_put;
    }

    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                req, pr, map->volume);
        goto out_unset_ctx;
    }

    if (req_ctx->orig_mapping->flags & MF_OBJECT_ZERO) {
        req_ctx->orig_mapping->state |= MF_OBJECT_WRITING;
        XSEGLOG2(&lc, I, "Object %s copy up completed. Pending writing.",
                orig_target);
    } else {
        req_ctx->orig_mapping->state |= MF_OBJECT_COPYING;
        XSEGLOG2(&lc, I, "Copying up object %s to %s", orig_target,
                new_target);
    }

    return req;


out_unset_ctx:
    remove_req_ctx(mio, req);
out_put:
    put_request(pr, req);
out_err:
    if (req_ctx->orig_mapping->flags & MF_OBJECT_ZERO) {
        XSEGLOG2(&lc, E, "Copying up zero object to %s failed", new_target);
    } else {
        XSEGLOG2(&lc, E, "Copying up object %s to %s failed",
                orig_target, new_target);
    }

    req_ctx->orig_mapping->state &= ~MF_OBJECT_COPYING;
    req_ctx->orig_mapping->state &= ~MF_OBJECT_WRITING;

    free(req_ctx);

    return NULL;
}

struct xseg_request *__object_write(struct peerd *peer, struct peer_req *pr,
                                    struct map *map, struct mapping *mn)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;

    req = map->mops->prepare_write_object(pr, map, mn);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot prepare write object");
        goto out_err;
    }

    r = __set_node(mio, req, mn);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
        goto out_put;
    }
    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                 req, pr, map->volume);
        goto out_unset_node;
    }
    XSEGLOG2(&lc, I, "Writing object %s \n\t"
             "Map: %s [%llu]",
             mn->object, map->volume, (unsigned long long) mn->objectidx);

    return req;

  out_unset_node:
    __set_node(mio, req, NULL);
  out_put:
    put_request(pr, req);
  out_err:
    XSEGLOG2(&lc, E, "Object write for object %s failed. \n\t"
             "(Map: %s [%llu]",
             mn->object, map->volume, (unsigned long long) mn->objectidx);
    return NULL;
}

static int __object_delete_delete_cb(struct peer_req *pr,
                                     struct xseg_request *req,
                                     struct mapping *mn)
{
    struct peerd *peer = pr->peer;
    struct map *map;
    struct xseg_request *xreq;
    struct mapping newmn;
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);

    mn->state &= ~MF_OBJECT_DELETING;

    map = mn->map;
    if (!map) {
        XSEGLOG2(&lc, E, "Object %s has no map back pointer", mn->object);
        return -1;
    }

    /* construct a tmp mapping for writing purposes */
    newmn = *mn;
    newmn.flags |= MF_OBJECT_DELETED;
    xreq = __object_write(peer, pr, map, &newmn);
    if (!xreq) {
        XSEGLOG2(&lc, E, "Object write returned error for object %s"
                 "\n\t of map %s [%llu]",
                 mn->object, map->volume, (unsigned long long) mn->objectidx);
        return -1;
    }
    r = __set_node(mio, xreq, mn);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
    }
    mn->state |= MF_OBJECT_WRITING;
    return 0;
}

static int __object_delete_write_cb(struct peer_req *pr,
                                    struct xseg_request *req,
                                    struct mapping *mn)
{
    struct peerd *peer = pr->peer;
    struct mapping tmp;
    char *data;

    //assert mn->state & MF_OBJECT_WRITING
    mn->state &= ~MF_OBJECT_WRITING;

    /* update object on cache */
    mn->flags |= MF_OBJECT_DELETED;
    return 0;
}

void object_delete_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct peerd *peer = pr->peer;
    struct mapping *mn = __get_node(mio, req);
    struct xseg_reply_hash *xreply;

    __set_node(mio, req, NULL);

    if (!mn) {
        XSEGLOG2(&lc, E, "Cannot get mapnode");
        mio->err = 1;
        goto out_err;
    }

    if (req->state & XS_FAILED) {
        XSEGLOG2(&lc, E, "Req failed");
        mn->state &= ~MF_OBJECT_DELETING;
        mn->state &= ~MF_OBJECT_WRITING;
        goto out_err;
    }
    if (req->op == X_WRITE) {
        if (__object_delete_write_cb(pr, req, mn) < 0) {
            goto out_err;
        }
        XSEGLOG2(&lc, I, "Object write of %s completed successfully",
                 mn->object);
        mio->pending_reqs--;
        signal_mapnode(mn);
        //put mapnode here to match get on do_destroy()
        put_mapnode(mn);
        signal_pr(pr);
    } else if (req->op == X_DELETE) {
        //      issue write_object;
        if (__object_delete_delete_cb(pr, req, mn) < 0) {
            goto out_err;
        }
        XSEGLOG2(&lc, I, "Object deletion of %s completed. "
                 "Pending writing.", mn->object);
    } else {
        //FIXME   wtf??
        ;
    }

  out:
    put_request(pr, req);
    return;

  out_err:
    mio->pending_reqs--;
    XSEGLOG2(&lc, D, "Mio->pending_reqs: %u", mio->pending_reqs);
    mio->err = 1;
    signal_pr(pr);
    goto out;
}


struct xseg_request *__object_delete(struct peer_req *pr, struct mapping *mn)
{
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    int r;

    XSEGLOG2(&lc, I, "Deleting mapnode %s", mn->object);

    req = get_request(pr, mapper->bportno, mn->object, mn->objectlen, 0);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request for object %s", mn->object);
        goto out_err;
    }

    req->op = X_DELETE;
    req->size = req->datalen;
    req->offset = 0;

    r = __set_node(mio, req, mn);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot set map node for object %s", mn->object);
        goto out_put;
    }
    r = send_request(pr, req);
    if (r < 0) {
        XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, object: %s",
                 req, pr, mn->object);
        goto out_unset_node;
    }
    mn->flags |= MF_OBJECT_DELETING;
    XSEGLOG2(&lc, I, "Object %s deletion pending", mn->object);

    mio->pending_reqs++;

    return req;

  out_unset_node:
    __set_node(mio, req, NULL);
  out_put:
    put_request(pr, req);
  out_err:
    XSEGLOG2(&lc, I, "Object %s deletion failed", mn->object);
    return NULL;
}

void hash_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);
    struct peerd *peer = pr->peer;
    struct mapping *mn = __get_node(mio, req);
    struct xseg_reply_hash *xreply;

    XSEGLOG2(&lc, I, "Callback of req %p", req);

    if (!mn) {
        XSEGLOG2(&lc, E, "Cannot get mapnode");
        mio->err = 1;
        goto out_nonode;
    }

    if (req->state & XS_FAILED) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Request failed");
        goto out;
    }

    if (req->serviced != req->size) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Serviced != size");
        goto out;
    }

    xreply = (struct xseg_reply_hash *) xseg_get_data(peer->xseg, req);
    if (xreply->targetlen != HEXLIFIED_SHA256_DIGEST_SIZE) {
        XSEGLOG2(&lc, E, "Reply targetlen != HEXLIFIED_SHA256_DIGEST_SIZE");
        mio->err = 1;
        goto out;
    }

    strncpy(mn->object, xreply->target, HEXLIFIED_SHA256_DIGEST_SIZE);
    mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
    mn->objectlen = HEXLIFIED_SHA256_DIGEST_SIZE;
    XSEGLOG2(&lc, D, "Received hash object %llu: %s (%p)",
             mn->objectidx, mn->object, mn);
    mn->flags = 0;

  out:
    put_mapnode(mn);
    __set_node(mio, req, NULL);
  out_nonode:
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}


int __hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map)
{
    struct mapperd *mapper = __get_mapperd(pr->peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    uint64_t i;
    struct mapping *mn, *hashed_mn;
    struct xseg_request *req;
    int r;

    mio->priv = 0;

    for (i = 0; i < map->nr_objs; i++) {
        mn = get_mapnode(map, i);
        if (!mn) {
            XSEGLOG2(&lc, E, "Cannot get mapnode %llu of map %s ",
                     "(nr_objs: %llu)", i, map->volume, map->nr_objs);
            return -1;
        }
        hashed_mn = get_mapnode(hashed_map, i);
        if (!hashed_mn) {
            XSEGLOG2(&lc, E, "Cannot get mapnode %llu of map %s ",
                     "(nr_objs: %llu)", i, hashed_map->volume,
                     hashed_map->nr_objs);
            put_mapnode(mn);
            return -1;
        }
        if (!(mn->flags & MF_OBJECT_ARCHIP)) {
            mio->priv++;
            strncpy(hashed_mn->object, mn->object, mn->objectlen);
            hashed_mn->objectlen = mn->objectlen;
            hashed_mn->object[hashed_mn->objectlen] = 0;
            hashed_mn->flags = mn->flags;

            put_mapnode(mn);
            put_mapnode(hashed_mn);
            continue;
        }

        req = get_request(pr, mapper->bportno, mn->object, mn->objectlen, 0);
        if (!req) {
            XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
            put_mapnode(mn);
            put_mapnode(hashed_mn);
            return -1;
        }

        req->op = X_HASH;
        req->offset = 0;
        req->size = map->blocksize;
        r = __set_node(mio, req, hashed_mn);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot set node");
            put_request(pr, req);
            put_mapnode(mn);
            put_mapnode(hashed_mn);
            return -1;
        }

        r = send_request(pr, req);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
                     req, pr, map->volume);
            put_request(pr, req);
            __set_node(mio, req, NULL);
            put_mapnode(mn);
            put_mapnode(hashed_mn);
            return -1;
        }
        mio->pending_reqs++;
        put_mapnode(mn);
    }

    return 0;
}

int hash_map(struct peer_req *pr, struct map *map, struct map *hashed_map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);

    XSEGLOG2(&lc, I, "Hashing map %s", map->volume);
    map->state |= MF_MAP_HASHING;
    mio->pending_reqs = 0;
    mio->cb = hash_cb;
    mio->err = 0;


    r = __hash_map(pr, map, hashed_map);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->cb = NULL;
    map->state &= ~MF_MAP_HASHING;
    if (mio->err) {
        XSEGLOG2(&lc, E, "Hashing map %s failed", map->volume);
        return -1;
    } else {
        XSEGLOG2(&lc, I, "Hashing map %s completed", map->volume);
        return 0;
    }
}
