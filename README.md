# coral-docker

You may have to allow insecure connections on localhost in order to connect locally. In Goolge Chrome this may be configured at [chrome://flags/#allow-insecure-localhost](chrome://flags/#allow-insecure-localhost).

Navigate to [localhost:3000/admin/install](http://localhost:3000/admin/install/) to finish local installation.

Then the admin dashboard will be available at [localhost:3000/admin/install](http://localhost:3000/admin/).

```sh
# build custom "onbuild" coral distribution (required)
# see https://docs.coralproject.net/talk/advanced-configuration for available build args
npm run docker:build

# start all containers
npm run docker:start

# stop all containers
npm run docker:stop
```
