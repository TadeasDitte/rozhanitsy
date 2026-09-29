#!/bin/sh
set -e

# Config/routes/views are cached at start-up rather than build time so the
# image stays environment-agnostic.
php artisan optimize --no-interaction

exec "$@"
