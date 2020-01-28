FROM coralproject/talk:4.11.4-onbuild
CMD export TALK_PORT=${PORT:-3000} TALK_ROOT_URL=${ROOT_URL:-http://127.0.0.1}:${PORT:-3000} && yarn start
