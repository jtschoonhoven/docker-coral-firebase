const jsonwebtoken = require('jsonwebtoken');
const { get } = require('lodash');
const jwtDecode = require('jwt-decode');
const UsersService = require('services/users');
const Settings = require('services/settings');
const TokensService = require('services/tokens');
const fetch = require('node-fetch');
const FormData = require('form-data');
const LocalStrategy = require('passport-local').Strategy;
const {
    ErrLoginAttemptMaximumExceeded,
    ErrAuthentication,
    ErrNotVerified,
} = require('errors');
const debug = require('debug')('talk:services:passport');
const _ = require('lodash');

// Create a redis client to use for authentication.
const { createClientFactory } = require('services/redis');
const client = createClientFactory();

const {
    JWT_ISSUER,
    JWT_AUDIENCE,
    JWT_ALG,
    RECAPTCHA_SECRET,
    RECAPTCHA_ENABLED,
    JWT_COOKIE_NAMES,
    JWT_USER_ID_CLAIM,
    ROOT_URL,
} = require('config');

const { jwt } = require('secrets');


/**
 * Validates that a user is allowed to login.
 * @param {User}     user the user to be validated
 * @param {Function} done the callback for the validation
 */
async function ValidateUserLogin(loginProfile, user, done) {
    if (!user) {
        return done(new Error('user not found'));
    }

    if (user.disabled) {
        return done(new ErrAuthentication('Account disabled'));
    }

    // If the user isn't a local user (i.e., a social user).
    if (loginProfile.provider !== 'local') {
        return done(null, user);
    }

    // The user is a local user, check if we need email confirmation.
    const { requireEmailConfirmation = false } = await Settings.select(
        'requireEmailConfirmation'
    );

    // If we have the requirement of checking that emails for users are
    // verified, then we need to check the email address to ensure that it has
    // been verified.
    if (requireEmailConfirmation) {
        // Get the profile representing the local account.
        let profile = user.profiles.find(profile => profile.id === loginProfile.id);

        // This should never get to this point, if it does, don't let this past.
        if (!profile) {
            throw new Error('ID indicated by loginProfile is not on user object');
        }

        // If the profile doesn't have a metadata field, or it does not have a
        // confirmed_at field, or that field is null, then send them back.
        if (_.get(profile, 'metadata.confirmed_at', null) === null) {
            return done(new ErrNotVerified());
        }
    }

    return done(null, user);
}

//==============================================================================
// JWT STRATEGY
//==============================================================================

// https://github.com/coralproject/talk/blob/64800ffaee8efdb1c72c2294f9cc899df5837c9a/services/jwt.js#L100
function verify(token, options, verifyingKey, callback) {
    const opts = _.omitBy(
        _.merge({}, options, { algorithms: [JWT_ALG], issuer: [JWT_ISSUER, ROOT_URL] }),
        _.isUndefined,
    );

    console.log(`Verifying token ${token}`);
    console.log(`Verifying with config:\n${JSON.stringify(opts, null, 2)}`);
    console.log(`Using public key ${verifyingKey}`);

    try {
        const decoded = jsonwebtoken.verify(token, verifyingKey, opts);
        console.log('Successfully verified token.');
        return callback(null, decoded);
    }
    catch (err) {
        console.log(`Error: Failed to verify token.`);
        return callback(err);
    }
}

const checkGeneralTokenBlacklist = jwt =>
    client()
        .get(`jtir[${jwt.jti}]`)
        .then(expiry => {
            if (expiry != null) {
                throw new ErrAuthentication('token was revoked');
            }
        });

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


// Extract the JWT from the 'Authorization' header with the 'Bearer' scheme.
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
    return verify(token, options, secretOrKey, (err, jwt) => {
        if (err) {
            return callback(err);
        }

        // Attach the original token onto the payload.
        return callback(false, { token, jwt });
    });
};

function secretOrKeyProvider(request, rawJwtToken, done) {
    let header;
    try {
        header = jwtDecode(rawJwtToken, { header: true });

        // Tokens might come from Coral (static keypair) or they might come from Firebase (rotating).
        // There will be a "kid" if the key rotates, otherwise we can immediately return the public key.
        if (!header.kid) {
            return done(null, jwt.verifiyingKey); // typo is intentional
        }
    }
    catch (err) {
        console.log(`Failed to decode token, falling back to static public key: ${err.message}`);
        return done(null, jwt.verifiyingKey); // typo is intentional
    }

    // This is a rotating key so we must first fetch the current public key from Firebase.
    fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')
        .then((res) => res.json())
        .then((data) => {
            // Get the public key from the response that matches this token's kid.
            const publicKey = get(data, header.kid);
            if (publicKey) {
                console.log(`Successfully fetched rotating public key.`);
                return done(null, publicKey);
            }
            // If the kid didn't match any keys, something is wrong. Fall back to global public key.
            console.log('No rotating public keys matched: falling back to static key.');
            return done(null, jwt.verifiyingKey);  // typo is intentional
        })
        .catch((err) => {
            // rethrow any network errors to be handled by outer try/catch
            console.log(`Network failure while fetching rotating public key, falling back to static: ${err.message}.`);
            return done(null, jwt.verifiyingKey);  // typo is intentional
        });
}

const jwtStrategy = new JwtStrategy(
    {
        // Prepare the extractor from the header.
        jwtFromRequest: ExtractJwt.fromExtractors([
            cookieExtractor,
            ExtractJwt.fromUrlQueryParameter('access_token'),
            ExtractJwt.fromAuthHeaderWithScheme('Bearer'),
        ]),

        // Use the secret passed in which is loaded from the environment. This can be
        // a certificate (loaded) or a HMAC key.
        // secretOrKey: jwt,

        secretOrKeyProvider,

        // Verify the issuer.
        issuer: JWT_ISSUER,

        // Verify the audience.
        audience: JWT_AUDIENCE,

        // Enable only the HS256 algorithm.
        algorithms: [JWT_ALG],

        // Pass the request object back to the callback so we can attach the JWT to
        // it.
        passReqToCallback: true,
    },
    async (req, { token, jwt }, done) => {
        // Load the user from the environment, because we just got a user from the
        // header.
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

//==============================================================================
// LOCAL STRATEGY
//==============================================================================

/**
 * This looks at the request headers to see if there is a recaptcha response on
 * the input request.
 */
const CheckIfRecaptcha = req => {
    let response = req.get('X-Recaptcha-Response');

    if (response && response.length > 0) {
        return true;
    }

    return false;
};

/**
 * This checks the user to see if the current email profile needs to get checked
 * for recaptcha compliance before being allowed to login.
 */
const CheckIfNeedsRecaptcha = (user, email) => {
    // Get the profile representing the local account.
    let profile = user.profiles.find(profile => profile.id === email);

    // This should never get to this point, if it does, don't let this past.
    if (!profile) {
        throw new Error('ID indicated by loginProfile is not on user object');
    }

    if (_.get(profile, 'metadata.recaptcha_required', false)) {
        return true;
    }

    return false;
};

/**
 * This sends the request details down Google to check to see if the response is
 * genuine or not.
 * @return {Promise} resolves with the success status of the recaptcha
 */
const CheckRecaptcha = async req => {
    // Ask Google to verify the recaptcha response: https://developers.google.com/recaptcha/docs/verify
    const form = new FormData();

    form.append('secret', RECAPTCHA_SECRET);
    form.append('response', req.get('X-Recaptcha-Response'));
    form.append('remoteip', req.ip);

    // Perform the request.
    let res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        body: form,
        headers: form.getHeaders(),
    });

    // Parse the JSON response.
    let json = await res.json();

    return json.success;
};

/**
 * This records a login attempt failure as well as optionally flags an account
 * for requiring a recaptcha in the future outside the temporary window.
 * @return {Promise} resolves with nothing if rate limit not exeeded, errors if
 *                   there is a rate limit error
 */
const HandleFailedAttempt = async (email, userNeedsRecaptcha) => {
    try {
        await UsersService.recordLoginAttempt(email);
    } catch (err) {
        if (
            err instanceof ErrLoginAttemptMaximumExceeded &&
            !userNeedsRecaptcha &&
            RECAPTCHA_ENABLED
        ) {
            debug(`flagging user email=${email}`);
            await UsersService.flagForRecaptchaRequirement(email, true);
        }

        throw err;
    }
};

const localStrategy = new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true,
    },
    async (req, email, password, done) => {
        // Normalize email
        email = email.toLowerCase();

        // We need to check if this request has a recaptcha on it at all, if it does,
        // we must verify it first. If verification fails, we fail the request early.
        // We can only do this obviously when recaptcha is enabled.
        let hasRecaptcha = CheckIfRecaptcha(req);
        let recaptchaPassed = false;
        if (RECAPTCHA_ENABLED && hasRecaptcha) {
            try {
                // Check to see if this recaptcha passed.
                recaptchaPassed = await CheckRecaptcha(req);
            } catch (err) {
                return done(err);
            }

            if (!recaptchaPassed) {
                try {
                    await HandleFailedAttempt(email);
                } catch (err) {
                    return done(err);
                }

                return done(null, false, { message: 'Incorrect recaptcha' });
            }
        }

        debug(`hasRecaptcha=${hasRecaptcha}, recaptchaPassed=${recaptchaPassed}`);

        // If the request didn't have a recaptcha, check to see if we did need one by
        // checking the rate limit against failed attempts on this email
        // address/login.
        if (!hasRecaptcha) {
            try {
                await UsersService.checkLoginAttempts(email);
            } catch (err) {
                if (err instanceof ErrLoginAttemptMaximumExceeded) {
                    // This says, we didn't have a recaptcha, yet we needed one.. Reject
                    // here.

                    try {
                        await HandleFailedAttempt(email);
                    } catch (err) {
                        return done(err);
                    }

                    return done(null, false, { message: 'Incorrect recaptcha' });
                }

                // Some other unexpected error occured.
                return done(err);
            }
        }

        // Let's find the user for which this login is connected to.
        let user;
        try {
            user = await UsersService.findLocalUser(email);
        } catch (err) {
            return done(err);
        }

        debug(`user=${user != null}`);

        // If the user doesn't exist, then mark this as a failed attempt at logging in
        // this non-existant user and continue.
        if (!user) {
            try {
                await HandleFailedAttempt(email);
            } catch (err) {
                return done(err);
            }

            return done(null, false, {
                message: 'Incorrect email/password combination',
            });
        }

        // Let's check if the user indeed needed recaptcha in order to authenticate.
        // We can only do this obviously when recaptcha is enabled.
        let userNeedsRecaptcha = false;
        if (RECAPTCHA_ENABLED && user) {
            userNeedsRecaptcha = CheckIfNeedsRecaptcha(user, email);
        }

        debug(`userNeedsRecaptcha=${userNeedsRecaptcha}`);

        // Let's check now if their password is correct.
        let userPasswordCorrect;
        try {
            userPasswordCorrect = await user.verifyPassword(password);
        } catch (err) {
            return done(err);
        }

        debug(`userPasswordCorrect=${userPasswordCorrect}`);

        // If their password wasn't correct, mark their attempt as failed and
        // continue.
        if (!userPasswordCorrect) {
            try {
                await HandleFailedAttempt(email, userNeedsRecaptcha);
            } catch (err) {
                return done(err);
            }

            return done(null, false, {
                message: 'Incorrect email/password combination',
            });
        }

        // If the user needed a recaptcha, yet we have gotten this far, this indicates
        // that the password was correct, so let's unflag their account for logins. We
        // can only do this obviously when recaptcha is enabled. The account wouldn't
        // have been flagged otherwise.
        if (RECAPTCHA_ENABLED && userNeedsRecaptcha) {
            try {
                await UsersService.flagForRecaptchaRequirement(email, false);
            } catch (err) {
                return done(err);
            }
        }

        // Define the loginProfile being used to perform an additional
        // verification.
        let loginProfile = { id: email, provider: 'local' };

        // Perform final steps to login the user.
        return ValidateUserLogin(loginProfile, user, done);
    }
);

module.exports = {
    passport: (passport) => {
        passport.use(jwtStrategy);
        passport.use(localStrategy);
    },
};
