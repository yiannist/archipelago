# Archipelago's Mapper re-design for GC

In this document we describe the GC-related actions that should be performed per
Mapper xseg_request operation that is relative to map updates.

## CREATE (X_CLONE w/o origin)

Creation of a new volume. No object updates => No GC action.

dispatch_accepted : 2152 -> handle_clone : 1937
-> do_create : 1437 (MF_CREATE | MF_EXCLUSIVE)

## SNAPSHOT (X_SNAPSHOT)

Snapshoting is the act of taking a copy of a state of a volume.

1) Lock map (src) & snap_map (dst) (XXX: Already locked with MF_EXCLUSIVE flag!)
2) Message GC queue: [RO -> RO+1, RW -> RW+2]
3) Write src epoch'
     |--> on fail: Message GC queue: [RO-1, RW-2]
            |--> on fail: Abort (STALE OBJECTS!)
4) Write dst epoch''
     |--> on fail: Message GC queue: [RO-1, RW-2]
5) Unlock map & snap_map
6) Continue

dispatch_accepted : 2152 -> handle_snapshot : 2067
-> do_snapshot : 737 (MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE) (XXX: Asserts src lock)
-> write_snapshot : 626 (MF_CREATE | MF_EXCLUSIVE) (XXX: Asserts dst lock)

## COPY-UP (X_MAPW)
## CLONE (X_CLONE w/ origin)
## COMPOSE (X_CREATE)
## REMOVE (X_DELETE)

--
NOTES:
- map_action(action, pr, name, namelen, flags) : 1896 (XXX: Does the locking!)
- get_ready_map(pr, name, namelen, flags) : 1869
