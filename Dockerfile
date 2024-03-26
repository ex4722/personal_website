###############
# Build Stage #
###############
FROM docker.io/razonyang/hugo:exts as builder
# Base URL
ARG HUGO_BASEURL=
ENV HUGO_BASEURL=${HUGO_BASEURL}
# Build site
COPY . /src
RUN hugo --minify --gc --enableGitInfo
# Set the fallback 404 page if defaultContentLanguageInSubdir is enabled, please replace the `en` with your default language code.
# RUN cp ./public/en/404.html ./public/404.html

###############
# Final Stage #
###############
FROM docker.io/nginxinc/nginx-unprivileged
COPY --from=builder /src/public /usr/share/nginx/html
