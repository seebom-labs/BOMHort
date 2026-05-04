# ---- Build stage ----
FROM node:22-alpine@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npx ng build --configuration=production

# ---- Serve stage ----
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# Remove default nginx config.
RUN rm /etc/nginx/conf.d/default.conf

# Add our custom nginx config.
COPY nginx.conf /etc/nginx/conf.d/seebom.conf

# Copy built Angular assets.
COPY --from=builder /app/dist/ui/browser /usr/share/nginx/html

# Create an empty custom-theme.css fallback (overridable via volume mount).
RUN touch /usr/share/nginx/html/custom-theme.css

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

