const Users = require('services/users');
const authz = require('middleware/authorization');


// When the JWT is passed to Talk, first it will be validated
// Next, Talk will attempt to locate a user in its DB using the token's sub claim,
// if the user is not found, the tokenUserNotFound hook will be called to create the user
async function _tokenUserNotFound({ jwt }) {
    jwt.username = jwt.username || jwt.email || jwt.sub; // ensure jwt.username
    console.log(`creating new user for "${jwt.username}"`);

    // Since the JWT has already been validated we can pass it's claims directly to upsertExternalUser
    const user = await Users.upsertExternalUser(
        null,
        jwt.sub,
        jwt.iss,
        jwt.username,
    );

    // Persisting email address in Talk is required only if sending notifications from Talk.
    // If email was included on the JWT we can add it to a "local" profile
    // and push that into the user's Profiles array.
    // To avoid duplication of Profiles, you may want add a check if user.wasUpserted
    // upsertExternalUser above will also create a profile as: { provider:jwt.iss, id:jwt.sub }
    const email = jwt.email.toLowerCase();
    user.profiles.push({ provider: 'local', id: email });

    // Then handle any additional User fields that you'd like to persist in Talk
    // In this example a "memberSince" claim containing a unix timestamp on the jwt
    // is used to overwrite created_at date
    // You can use the User.metadata property to store additional custom user details
    user.created_at = jwt.memberSince ? new Date(jwt.memberSince * 1000) : Date.now();

    // Finally, save and return the User that was created
    await user.save();
    console.log(`created new user ${JSON.stringify(user, null, 2)}`);
    return user;
}


// At this point we've handled creating new users,
// now let's handle updating a user that was created by our tokenUserNotFound hook.
// This implementation assumes that the external auth service calls the TALK_ROOT_URL/plugin/update-user endpoint
// with a valid jwt token anytime a user is update needs to be passed to Talk
// First we add the `/plugin/update-user`` route and secure it with ADMIN level permissions
function _router(router) {
    router.post('/plugin/update-user', authz.needed('ADMIN'), async (req, res, next) => {
        const {
            body: { token },
            context: { connectors: { models: { User } } },
        } = req;

        // Since the token is being passed directly to the route in this case,
        // we need to parse it and should validate its claims
        try {
            const { sub, username, email, iss } = JSON.parse(
                Buffer.from(token.split('.')[1], 'base64').toString()
            );
            // CUSTOM: fallbacks for username
            username = username || email || sub;
            // Finally we call findOneAndUpdate to locate, update, and return the User from Talk's DB
            // Be sure to update any and all fields that were set by the tokenUserNotFoundHook
            let user = await User.findOneAndUpdate(
                { $or: [{ sub }, { 'profiles.id': sub }] },
                {
                    $set: {
                        username: username,
                        lowercaseUsername: username.toLowerCase(),
                        profiles: [
                            {
                                provider: 'local',
                                id: email,
                            },
                            {
                                provider: iss,
                                id: sub,
                            },
                        ],
                    },
                },
                {
                    new: true,
                }
            );
            return res.json({ user });
        } catch (e) {
            return next(e);
        }
    }
    );
}

module.exports = {
    tokenUserNotFound: _tokenUserNotFound,
    router: _router,
};
