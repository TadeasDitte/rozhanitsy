# syntax=docker/dockerfile:1

ARG PHP_IMAGE=dunglas/frankenphp:1-php8.5-bookworm
ARG NODE_IMAGE=node:22-bookworm-slim

FROM ${NODE_IMAGE} AS node

FROM ${PHP_IMAGE} AS base

RUN install-php-extensions \
        bcmath \
        intl \
        opcache \
        pcntl \
        pdo_pgsql \
        pgsql \
        redis \
        zip \
    && cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY docker/php.ini "$PHP_INI_DIR/conf.d/zz-app.ini"

WORKDIR /app

# PHP dependencies (no dev) — installed before the app code so the layer caches.
FROM base AS vendor

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --no-interaction --prefer-dist

COPY . .
RUN composer dump-autoload --no-dev --optimize --classmap-authoritative \
    && mkdir -p storage/app/tmp storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs bootstrap/cache

# Frontend assets. Needs PHP too, since the Wayfinder vite plugin runs artisan.
FROM vendor AS assets

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && corepack enable pnpm

RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 pnpm install --frozen-lockfile \
    && pnpm run build

FROM base AS app

ARG USER=www-data

COPY --from=vendor --chown=${USER}:${USER} /app /app
COPY --from=assets --chown=${USER}:${USER} /app/public/build /app/public/build
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint

RUN setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/frankenphp \
    && chown -R ${USER}:${USER} /config/caddy /data/caddy

USER ${USER}

ENV APP_ENV=production \
    APP_DEBUG=false \
    LOG_CHANNEL=stderr \
    SERVER_NAME=:80

EXPOSE 80 443 443/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost/up || exit 1

ENTRYPOINT ["entrypoint"]
CMD ["frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"]
