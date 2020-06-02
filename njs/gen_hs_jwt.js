function generate_hs256_jwt(claims, key, valid) {
    var header = { typ: "JWT",  alg: "HS256" };
	var claims = Object.assign(claims, {exp: Math.floor(Date.now()/1000) + valid});

    var s = [header, claims].map(JSON.stringify)
                            .map(v=>v.toUTF8())
                            .map(v=>v.toString('base64url'))
                            .join('.');

    var h = require('crypto').createHmac('sha256', key);

    return s + '.' + h.update(s).digest().toString('base64url');
}

function jwt(r) {
    var claims = {
        iss: "nginx",
        sub: "alice",
        foo: 123,
        bar: "qq",
        zyx: false
    };

    return generate_hs256_jwt(claims, process.env.JWT_GEN_KEY, 600);
}

export default {jwt};
