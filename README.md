# coral-docker

Extends the [coralproject/talk](https://github.com/coralproject/talk) commenting platform for use with Firebase.

## Summary
This is a configuration of [coralproject/talk](https://github.com/coralproject/talk) [v4.11.4](https://github.com/coralproject/talk/releases/tag/v4.11.4) for use with Google's Firebase. This allows Firebase users to plug in Coral as a commenting platform while using Firebase to manage users and authentication. Users that have logged in with Firebase are transparently logged in to Coral Talk with account details securely shared using JWTs.

## Setup

### 1. Firebase Setup
Before you begin you must have an existing Firebase project with at least one sign-in method configured. Make note of your project ID (e.g. `myproj-abc123`) and then generate a private key from the page at `Project settings > Service accounts`. This will generate a JSON file that contains your private key. Save it somewhere secure (do NOT check it in).

### 2. Generate Firebase Keypair
Coral Talk needs to use the same public/private key that Firebase uses. You have just dowloaded the private key, but you must extract the public key manually. This will be the most complex step in the setup. To begin, open up the JSON file from the previous step and copy just the private key into a new file, replacing encoded newlines `\n` with line breaks. Save this file somewhere secure with a name like `firebase.pem`. It should look something like this:

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anG
cmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYD
...
-----END PRIVATE KEY-----
```

Fortunately this private key also encodes its corresponding public key. You can extract it using the following `openssl` command:

```sh
# save the public key to a file named firebase.pub
openssl rsa -pubout -in path/to/firebase.pem -out /path/to/firebase.pub
```

Now you should have a file named something like `firebase.pub` that looks like this:

```
-----BEGIN PUBLIC KEY-----
MIIFaDCCBFCgAwIBAgISESHkvZFwK9Qz0KsXD3x8p44aMA0GCSqGSIb3DQEBCwUA
VQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
...
-----END PUBLIC KEY-----
```

You will use this keypair in step 3.

### 3. Connect to Firebase
To connect to your Firebase project, you must create a file named `.env` in the `private/` directory. This will contain all configuration that is specific to your project. For local development you need to set just three variables:

```
TALK_JWT_AUDIENCE=<YOUR FIREBASE PROJECT ID>
TALK_JWT_ISSUER=https://securetoken.google.com/<YOUR FIREBASE PROJECT ID>
TALK_JWT_SECRET={"public": "<YOUR FIREBASE PRIVATE KEY>", "private": "<YOUR FIREBASE PUBLIC KEY>"}
```

**IMPORTANT:** when adding your public and private keys, Coral Talk requires for each to be a single line with newlines escaped as `\\n` (note double backslash).

Once you have pasted in your Project ID and keypairs from the steps above you are ready to build!

### 4. Build and Start the Docker Image
With `docker` and `npm` installed, building is as simple as `npm run: docker:build`. If it is your first time running this command it will take a few minutes. Once the image is built, you can run the image and its dependencies with `npm run docker:start`.

### 5. Configure Coral Talk
The rest of the setup takes place in your browser using Coral Talk's own install wizard. Navigate to [localhost:3000/admin/install](http://localhost:3000/admin/install/) to finish the installation. Make sure to whitelist 127.0.0.1:3000 and 127.0.0.1:8080 (or wherever you are running your local Firebase app). Now the admin dashboard will be available at [localhost:3000/admin](http://localhost:3000/admin/). That's it!

## Run the Demo App
Log in to the Firebase console for your project and navigate to `Project settings > General` then copy your Firebase SDK snippet (just the config part, excluding the CDN scripts). It should look like this:

```html
<script>
  // Your web app's Firebase configuration
  var firebaseConfig = {
    apiKey: "...",
    authDomain: "...",
    databaseURL: "...",
    projectId: "...",
    storageBucket: "...",
    messagingSenderId: "...",
    appId: "...",
    measurementId: "..."
  };
  // Initialize Firebase
  firebase.initializeApp(firebaseConfig);
  firebase.analytics();
</script>
```

Open up `demo/index.html` and paste in this snippet (look for the `REPLACE THIS BLOCK WITH YOUR FIREBASE SDK SNIPPET` comment). Serve the HTML file locally with `npm run demo` then navigate to the URL (typically [127.0.0.1:8080](http://127.0.0.1:8080)).

## Troubleshooting

### SSL connection errors in development
In your `private/.env` file, set `TALK_HELMET_CONFIGURATION={"hsts": false}`.

```sh
# build custom "onbuild" coral distribution (required)
# see https://docs.coralproject.net/talk/advanced-configuration for available build args
npm run docker:build

# start all containers
npm run docker:start

# stop all containers
npm run docker:stop
```
