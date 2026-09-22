# ---- Build stage ----
# Pin to host platform to avoid QEMU emulation for npm ci (ARM64 crashes under QEMU).
# The output is static HTML/JS/CSS — platform-independent.
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:dbaa92e5758cbbcf85d65d5403fdb530fe3442cbe8c6dbfb7ef23365450d5070 AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npx ng build --configuration=production

# ---- Serve stage ----
FROM nginx:1.31-alpine@sha256:62ff2089abf5a9ed33bd232895bef5e22f7bb4b200675cec49a5ebc48e3d4ac8

# Remove default nginx config.
RUN rm /etc/nginx/conf.d/default.conf

# Default values for envsubst — overridable at runtime via container env.
# Empty SERVICE_TOKEN means the UI's nginx will NOT inject an Authorization
# header on proxied API calls (compatible with AUTH_ENABLED=false on the API).
ENV SERVICE_TOKEN=""

# Install the nginx config as a template. The nginx official image runs
# /docker-entrypoint.d/20-envsubst-on-templates.sh at startup, which renders
# /etc/nginx/templates/*.template into /etc/nginx/conf.d/*.conf using envsubst.
COPY nginx.conf.template /etc/nginx/templates/bomhort.conf.template

# Install the auth-header init script (sourced before envsubst runs).
COPY docker-entrypoint.d/15-bomhort-auth.envsh /docker-entrypoint.d/15-bomhort-auth.envsh
RUN chmod +x /docker-entrypoint.d/15-bomhort-auth.envsh

# Copy built Angular assets.
COPY --from=builder /app/dist/ui/browser /usr/share/nginx/html

# Create an empty custom-theme.css fallback (overridable via volume mount).
RUN touch /usr/share/nginx/html/custom-theme.css

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

