#!/usr/bin/env python3

import os
import tarfile
import getopt
import sys
import re
import hashlib
import psycopg2

psql_ip = ""


def _md5_stream(fobj):
    """MD5 of a file object, read in 64 KiB blocks (members can be huge)."""
    hasher = hashlib.md5()
    for block in iter(lambda: fobj.read(65536), b""):
        hasher.update(block)
    return hasher.hexdigest()


def getFileHashes(infile):
    files = list()
    links = list()
    with tarfile.open(infile) as t:
        for f in t.getmembers():
            if f.isfile():
                # we use f.name[1:] to get rid of the . at the beginning of the path
                files.append(
                    (
                        f.name[1:],
                        _md5_stream(t.extractfile(f)),
                        f.uid,
                        f.gid,
                        f.mode,
                    )
                )
            elif f.issym():
                links.append((f.name[1:], f.linkpath))
    return (files, links)


def getOids(objs, cur):
    # hashes ... all the hashes in the tar file
    hashes = sorted(set(x[1] for x in objs))
    if not hashes:
        return {}

    query = """SELECT id,hash FROM object WHERE hash = ANY(%(hashes)s)"""
    cur.execute(query, {"hashes": hashes})
    res = [(int(x), y) for (x, y) in cur.fetchall()]

    missingHashes = set(hashes).difference(set(y for (_, y) in res))

    if missingHashes:
        res += createObjects(missingHashes, cur)

        # rows another process inserted meanwhile (ON CONFLICT DO NOTHING
        # returns nothing for them) are looked up again
        known = set(y for (_, y) in res)
        late = sorted(set(hashes).difference(known))
        if late:
            cur.execute(query, {"hashes": late})
            res += [(int(x), y) for (x, y) in cur.fetchall()]

    return dict([(y, x) for (x, y) in res])


def createObjects(hashes, cur):
    # object.hash is UNIQUE (database/schema): a duplicate is expected when
    # another run inserted the same hash, anything else must surface.
    query = (
        """INSERT INTO object (hash) VALUES (%(hash)s) """
        """ON CONFLICT (hash) DO NOTHING RETURNING id"""
    )
    res = list()
    for h in sorted(set(hashes)):
        cur.execute(query, {"hash": h})
        row = cur.fetchone()
        if row:
            res.append((int(row[0]), h))
    return res


def insertObjectToImage(iid, files2oids, links, cur):
    # object_to_image has UNIQUE (oid, iid, filename): re-importing the same
    # image must not fail, but real database errors are raised to the caller.
    query = (
        """INSERT INTO object_to_image (iid, oid, filename, regular_file, uid, gid, permissions) """
        """VALUES (%(iid)s, %(oid)s, %(filename)s, %(regular_file)s, %(uid)s, %(gid)s, %(mode)s) """
        """ON CONFLICT (oid, iid, filename) DO NOTHING"""
    )

    cur.executemany(
        query,
        [
            {
                "iid": iid,
                "oid": x[1],
                "filename": x[0][0],
                "regular_file": True,
                "uid": x[0][1],
                "gid": x[0][2],
                "mode": x[0][3],
            }
            for x in files2oids
        ],
    )
    cur.executemany(
        query,
        [
            {
                "iid": iid,
                "oid": 1,
                "filename": x[0],
                "regular_file": False,
                "uid": None,
                "gid": None,
                "mode": None,
            }
            for x in links
        ],
    )


def process(iid, infile):
    global psql_ip
    (files, links) = getFileHashes(infile)

    dbh = psycopg2.connect(
        database="firmware", user="firmadyne", password=os.environ.get("FIRMAE_DB_PASSWORD", "firmadyne"), host=psql_ip
    )
    try:
        cur = dbh.cursor()
        oids = getOids(files, cur)

        # one row per file: files with identical content keep every name
        file2oid = [
            ((filename, uid, gid, mode), oids[h])
            for (filename, h, uid, gid, mode) in files
        ]

        insertObjectToImage(iid, file2oid, links, cur)
        dbh.commit()
    except BaseException:
        dbh.rollback()
        raise
    finally:
        dbh.close()


def main():
    global psql_ip
    infile = iid = None
    opts, argv = getopt.getopt(sys.argv[1:], "f:i:h:")
    for k, v in opts:
        if k == "-i":
            iid = int(v)
        if k == "-f":
            infile = v
        if k == "-h":
            psql_ip = v

    if infile and not iid:
        m = re.search(r"(\d+)\.tar\.gz", infile)
        if m:
            iid = int(m.group(1))

    if not infile or iid is None:
        print("tar2db: usage: tar2db.py -f <file.tar.gz> [-i <iid>] [-h <host>]",
              file=sys.stderr)
        return 2

    try:
        process(iid, infile)
    except Exception as e:
        print("tar2db: failed: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
