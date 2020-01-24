const _ = require('lodash');
const jwtDecode = require('jwt-decode');
const fetch = require('node-fetch');
const { get } = require('lodash');

const UsersService = require('services/users');
const TokensService = require('services/tokens');
const { createClientFactory } = require('services/redis');
const { ErrAuthentication } = require('errors');

// Create a redis client to use for authentication.
const client = createClientFactory();

const {
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_ALG,
    JWT_COOKIE_NAMES,
    JWT_USER_ID_CLAIM,
} = require('config');

const { jwt } = require('secrets');


const checkGeneralTokenBlacklist = (jwt) => {
    client()
        .get(`jtir[${jwt.jti}]`)
        .then(expiry => {
            if (expiry != null) {
                throw new ErrAuthentication('token was revoked');
            }
        });
}

/**
 * Check if the given token is already blacklisted, throw an error if it is.
 */
const CheckBlacklisted = async jwt => {
    // Check to see if this is a PAT.
    if (jwt.pat) {
        return TokensService.validate(get(jwt, JWT_USER_ID_CLAIM), jwt.jti);
    }

    // It wasn't a PAT! Check to see if it is valid anyways.
    await checkGeneralTokenBlacklist(jwt);

    return null;
};

const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

let cookieExtractor = req => {
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

// Override the JwtVerifier method on the JwtStrategy so we can pack the
// original token into the payload.
JwtStrategy.JwtVerifier = (token, secretOrKey, options, callback) => {
    return jwt.verify(token, options, (err, jwt) => {
        if (err) {
            return callback(err);
        }
        // Attach the original token onto the payload.
        return callback(false, { token, jwt });
    });
};


function secretOrKeyProvider(request, rawJwtToken, done) {
    let token;
    try {
        token = jwtDecode(rawJwtToken);
    }
    catch (err) {
        return done(err);
    }
    try {
        const header = jwtDecode(rawJwtToken, { header: true });
        fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')
            .then((res) => res.json())
            .then((data) => {
                const publicKey = get(data, header.kid);
                if (publicKey) {
                    return done(null, publicKey);
                }
                const err = new Error(`no public key in ${JSON.stringify(data)} exists for kid in ${JSON.stringify(header)}`);
                return done(err);
            })
            .catch(done);
    }
    catch (err) {
        return done(err);
    }
}


const jwtStrategy = new JwtStrategy({
    // Prepare the extractor from the header.
    jwtFromRequest: ExtractJwt.fromExtractors([
        cookieExtractor,
        ExtractJwt.fromUrlQueryParameter('access_token'),
        ExtractJwt.fromAuthHeaderWithScheme('Bearer'),
    ]),

    // Use the secret passed in which is loaded from the environment. This can be
    // a certificate (loaded) or a HMAC key.
    // secretOrKey: jwt,

    secretOrKeyProvider: secretOrKeyProvider,

    // Verify the issuer.
    issuer: JWT_ISSUER,

    // Verify the audience.
    audience: JWT_AUDIENCE,

    // Enable only the HS256 algorithm.
    algorithms: [JWT_ALG],

    // Pass the request object back to the callback so we can attach the JWT to it
    passReqToCallback: true,
},
    async (req, { token, jwt }, done) => {
        console.log(`verifying token for ${jwt.username}`);
        // Load the user from the environment, because we just got a user from the header
        try {
            // Check to see if the token has been revoked
            let user = await CheckBlacklisted(jwt);

            if (user === null) {
                // Try to get the user from the database or crack it from the token and
                // plugin integrations.
                user = await UsersService.findOrCreateByIDToken(
                    get(jwt, JWT_USER_ID_CLAIM),
                    { token, jwt }
                );
            }

            // Attach the JWT to the request.
            req.jwt = jwt;

            return done(null, user);
        } catch (e) {
            return done(e);
        }
    }
);


module.exports = {
    passport: (passport) => {
        passport.use(jwtStrategy);
    }
};
