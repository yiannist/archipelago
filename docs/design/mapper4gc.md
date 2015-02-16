# Archipelago's Mapper re-design for GC

In this document we describe the GC-related actions that should be performed per
Mapper xseg_request operation that is relative to map updates.

## CREATE (X_CLONE w/o origin)

Creation of a new volume. No object updates => No GC action.

dispatch_accepted : 2152 -> handle_clone : 1937
-> do_create : 1437 (MF_CREATE | MF_EXCLUSIVE)
(-> write_map)

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
(-> write_map)

## COPY-UP (X_MAPW)

Copy-up is a CoW operation. It takes place when the mapper has to write to RO
object.

1) Lock dst
2) Create new object
     |--> on fail: Abort w/ IO error
3) Update map
     |--> on fail: Abort w/ IO error
4) Message GC queue: [RO-1]
     |--> on fail: Log (STALE RO OBJECT!)
5) Unlock dst
6) Continue

dispatch_accepted : 2152 -> handle_mapw : 2002
-> do_mapw : 1099 (MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE | MF_FORCE) (XXX: Asserts dst lock)
-> req2objs : 444
-> do_copyups : 361
(-> write_map)

## CLONE (X_CLONE w/ origin)

Cloning is the creation of a RO volume from a snapshot.

1) Lock map (parent) & clone_map (dst)
2) Message GC queue: [RO+1] for overlapped size
     |--> on fail: Abort
3) Write dst epoch'
     |--> on fail: Message GC queue: [RO-1]
            |--> on fail: Abort and Log (STALE OBJECTS!)
4) Unlock map & clone_map
5) Continue

dispatch_accepted : 2152 -> handle_clone : 1937
-> do_clone : 1312 (MF_LOAD | MF_ARCHIP) (XXX: Asserts src lock)
(-> create_map : 316 (MF_ARCHIP))
-> write_clone : 1129 (MF_CREATE | MF_EXCLUSIVE) (XXX: Asserts dst lock)
(-> write_map)

## COMPOSE (X_CREATE)

Composition is the creation of a new Pithos volume.

1) Lock map
2) Message GC queue: [RO+1]CAS
     |--> on fail: Abort
3) Write map
     |--> on fail: Message GC queue: [RO-1]CAS
            |--> on fail: Abort and Log (STALE OBJECTS!)
4) Unlock map
5) Continue

dispatch_accepted : 2152 -> handle_create : 1968
-> do_compose : 1574 (MF_CREATE | MF_EXCLUSIVE) (XXX: Asserts map lock)

## REMOVE (X_DELETE)

Deletion of a map (=> deletion of a volume).

1) Lock map
2) Mark map as 'deleted'
     |--> on fail: Abort
3) Message GC queue: ?
     |--> on fail: Log (STALE OBJECTS!)
4) Unlock map
5) Continue

dispatch_accepted : 2152 -> handle_destroy : 2018
-> do_destroy : 798 (MF_ARCHIP | MF_LOAD | MF_EXCLUSIVE) (XXX: Asserts map lock)
(-> object_delete)
(-> delete_map)

--
NOTES:
- map_action(action, pr, name, namelen, flags) : 1896 (XXX: Does the locking!)
- get_ready_map(pr, name, namelen, flags) : 1869
- get_mapping(map, start + i) : 161
