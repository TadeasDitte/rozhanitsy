#!/bin/sh
set -e

# Config/routes/views are cached at start-up rather than build time so the
# image stays environment-agnostic.
php artisan optimize --no-interaction

if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    php artisan migrate --force --no-interaction
fi

exec "$@"
