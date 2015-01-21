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
#ifndef MAPPER_HELPERS_H
#define MAPPER_HELPERS_H

/* Returns a pointer to a tempororary NULL terminated string.
 * The buffer that holds the string is statically allocated and shared among all
 * invocations of the function.
 *
 * Supports up to XSEG_MAX_TARGETLEN strings. Returns NULL if targetlen larger.
 */
char *null_terminate(char *target, uint32_t targetlen);

/* Helpers to support most frequest XSEG request operations */
int send_request(struct peer_req *pr, struct xseg_request *req);
struct xseg_request *get_request(struct peer_req *pr, xport dst, char *target,
                                 uint32_t targetlen, uint64_t datalen);
void put_request(struct peer_req *pr, struct xseg_request *req);

#endif /* end of include guard */
