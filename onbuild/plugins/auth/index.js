const Users = require('services/users');


// When the JWT is passed to Talk, first it will be validated
// Next, Talk will attempt to locate a user in its DB using the token's sub claim,
// if the user is not found, the tokenUserNotFound hook will be called to create the user
async function _tokenUserNotFound({ jwt }) {
    console.log(`creating new user for ${jwt.email} named "${jwt.name}"`);
    jwt.username = jwt.name || jwt.username || jwt.email || 'unknown';

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


module.exports = {
    tokenUserNotFound: _tokenUserNotFound,
};
