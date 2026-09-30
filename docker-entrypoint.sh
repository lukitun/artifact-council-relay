#!/bin/sh
# Runs ac-relay in /work, the directory compose mounts (the one holding compose.yaml), as the user
# that owns it, so .env and .local/ stay that user's on the host. Nothing is ever chowned: a
# root-owned directory (extracted as root, or any directory under rootless Docker or Podman, where
# the host user is uid 0 here) keeps root as the owner and runs as container root, with every
# capability dropped (compose.yaml) so it can open only what that owner can.
set -e
cd /work
uid=$(stat -c %u .) gid=$(stat -c %g .)
if [ "$uid" = 0 ]; then
  exec node /app/ac-relay.mjs "$@"
fi
exec setpriv --reuid="$uid" --regid="$gid" --clear-groups node /app/ac-relay.mjs "$@"
