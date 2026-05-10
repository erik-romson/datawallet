#!/bin/bash
# Shadow pg_isready so the readiness check only passes after init scripts
# have completed. The postgres entrypoint runs init scripts against a
# temporary server that listens *only* on the Unix socket, then stops it
# and starts the permanent server (TCP + Unix). By forcing TCP via
# -h localhost, this check inherently waits for init (including
# bin/db-init.sql) to finish.
exec /usr/lib/postgresql/16/bin/pg_isready -h localhost "$@"
