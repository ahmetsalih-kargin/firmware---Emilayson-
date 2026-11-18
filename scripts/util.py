#!/usr/bin/env python3

import os
import sys
import psycopg2
import hashlib


def io_md5(target):
    blocksize = 65536
    hasher = hashlib.md5()

    with open(target, "rb") as ifp:
        buf = ifp.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = ifp.read(blocksize)
        return hasher.hexdigest()


def db_port():
    """FIRMAE_DB_PORT, or None when unset/empty: libpq then uses its default
    (PGPORT, else 5432), as before."""
    return os.environ.get("FIRMAE_DB_PORT") or None


def _connect(psql_ip):
    return psycopg2.connect(
        database="firmware", user="firmadyne", password=os.environ.get("FIRMAE_DB_PASSWORD", "firmadyne"), host=psql_ip,
        port=db_port()
    )


def query_(query, psql_ip, params=None):
    """Return the first row, or None when there is no row.

    Database errors (connection, SQL) are raised as psycopg2.Error; they are
    NOT the same thing as "no result".
    """
    dbh = _connect(psql_ip)
    try:
        cur = dbh.cursor()
        try:
            cur.execute(query, params)
            return cur.fetchone()
        finally:
            cur.close()
    finally:
        dbh.close()


def get_iid(infile, psql_ip):
    md5 = io_md5(infile)
    image_id = query_("SELECT id FROM image WHERE hash = %s", psql_ip, (md5,))

    if image_id:
        return image_id[0]
    else:
        return ""


def get_brand(infile, psql_ip):
    md5 = io_md5(infile)
    brand = query_(
        "SELECT brand.name FROM image JOIN brand ON brand.id = image.brand_id "
        "WHERE image.hash = %s",
        psql_ip,
        (md5,),
    )

    if brand:
        return brand[0]
    else:
        return ""


def check_connection(psql_ip):
    try:
        dbh = _connect(psql_ip)
        dbh.close()
        return 0
    except Exception:
        return 1


def main(argv):
    [infile, psql_ip] = argv[2:4]
    try:
        if argv[1] == "get_iid":
            print(get_iid(infile, psql_ip))
        if argv[1] == "get_brand":
            print(get_brand(infile, psql_ip))
        if argv[1] == "check_connection":
            return check_connection(psql_ip)
    except (psycopg2.Error, OSError) as e:
        # stdout stays empty so callers can tell "error" from "no record"
        print("util.py: %s failed: %s" % (argv[1], str(e).strip() or type(e).__name__),
              file=sys.stderr)
        return 1
    return 0


# command line
if __name__ == "__main__":
    sys.exit(main(sys.argv))
