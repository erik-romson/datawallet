#!/bin/bash
# Shadow pg_isready: TCP-only check ensures we wait for the permanent server.
# The temp init server is Unix-socket-only; -h 127.0.0.1 forces IPv4 TCP.
# -t 5 caps the SYN phase; outer timeout 5 caps post-connect auth wait.
exec timeout 5 /usr/lib/postgresql/16/bin/pg_isready -h 127.0.0.1 -t 5 "$@"
