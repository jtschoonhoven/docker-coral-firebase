const { get } = require('lodash');
const jwtDecode = require('jwt-decode');
const jsonwebtoken = require('jsonwebtoken');
const fetch = require('node-fetch');

const authz = require('middleware/authorization');

const { JWT_COOKIE_NAMES, JWT_ALG, JWT_ISSUER, ROOT_URL, JWT_AUDIENCE } = require('config');


let cookieTokenExtractor = (req) => {
    if (req && req.cookies) {
        // Walk over all the cookie names in JWT_COOKIE_NAMES.
        for (const cookieName of JWT_COOKIE_NAMES) {
            // Check to see if that cookie is set.
            if (
                cookieName in req.cookies &&
                req.cookies[cookieName] !== null &&
                req.cookies[cookieName].length > 0
            ) {
                return req.cookies[cookieName];
            }
        }
    }
    return null;
};


// return decoded key on success, throws error on failure
function verifyToken(token, publicKey) {
    const options = {
        algorithms: [JWT_ALG],
        issuer: [JWT_ISSUER, ROOT_URL],
        audience: JWT_AUDIENCE,
    };

    console.log(`Verifying token ${token}`);
    console.log(`Verifying with config:\n${JSON.stringify(options, null, 2)}`);
    console.log(`Using public key ${publicKey}`);

    return jsonwebtoken.verify(token, publicKey, options);
}


async function getPublicKey(rawToken) {
    const header = jwtDecode(rawToken, { header: true });

    if (!header.kid) {
        throw new Error('Kid missing in token header.')
    }

    // This is a rotating key so we must first fetch the current public key from Firebase.
    const res = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
    const data = await res.json();

    // Get the public key from the response that matches this token's kid.
    const publicKey = get(data, header.kid);

    if (publicKey) {
        return publicKey;
    }
    throw new Error('No public keys matched the given kid.');
}


// At this point we've handled creating new users,
// now let's handle updating a user that was created by our tokenUserNotFound hook.
// This implementation assumes that the external auth service calls the TALK_ROOT_URL/plugin/update-username endpoint
// with a valid jwt token anytime a user is update needs to be passed to Talk
// First we add the `/plugin/update-username`` route and secure it with COMMENTER level permissions
function _router(router) {
    router.post('/plugin/update-username', authz.needed('COMMENTER'), async (req, res, next) => {
        const token = req.body.token || req.query.access_token || cookieTokenExtractor(req);
        const username = req.body.username || req.query.username;
        const User = req.context.connectors.models.User;

        if (!token) {
            const err = new Error('Failed to locate token in request body, params, or cookie.');
            console.log(err.message);
            return next(err);
        }

        if (!username) {
            const err = new Error('Failed to locate new username in request body or params.');
            console.log(err.message);
            return next(err);
        }

        let jwt;
        try {
            console.log(`Fetching publicKey for token:\n${token}`);
            const publicKey = await getPublicKey(token);

            console.log('Successfully fetched publicKey: verifying token.');
            jwt = verifyToken(token, publicKey);
        }
        catch (err) {
            console.log(`Error while verifying token: ${err.message}`);
            return next(err);
        }
        console.log(`Successfully validated and decoded token:\n${JSON.stringify(jwt, null, 2)}`);

        try {
            let user = await User.findOneAndUpdate(
                { $or: [{ sub: jwt.sub }, { 'profiles.id': jwt.sub }] },
                {
                    $set: {
                        username: username,
                        lowercaseUsername: username.toLowerCase(),
                    },
                },
                {
                    new: true,
                }
            );
            return res.json({ user });
        } catch (e) {
            console.log(`Error while persisting new username: ${e.message}`);
            return next(e);
        }
    }
    );
}

module.exports = {
    router: _router,
};
