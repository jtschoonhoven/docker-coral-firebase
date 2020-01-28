FROM coralproject/talk:4.11.4-onbuild
ENV PORT ${PORT:-3000}
ENV TALK_ROOT_URL ${ROOT_URL:-http://127.0.0.1}:${PORT}
CMD export TALK_PORT="$PORT" TALK_ROOT_URL="${TALK_ROOT_URL}:${PORT}" && yarn start
