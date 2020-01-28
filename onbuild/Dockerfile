FROM coralproject/talk:4.11.4-onbuild
# Coral requires TALK_PORT to be set, but Heroku sets PORT dynamically at runtime.
# This means that the ENV command can't be used here, but we can export the vars when the app starts.
CMD export TALK_PORT=${PORT:-3000} TALK_ROOT_URL=${ROOT_URL:-http://127.0.0.1} && yarn start
