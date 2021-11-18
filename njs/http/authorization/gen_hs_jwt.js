async function generate_hs256_jwt(init_claims, key, valid) {
    let header = { typ: "JWT",  alg: "HS256" };
    let claims = Object.assign(init_claims, {exp: Math.floor(Date.now()/1000) + valid});

    let s = [header, claims].map(JSON.stringify)
                            .map(v=>Buffer.from(v).toString('base64url'))
                            .join('.');

    let wc_key = await crypto.subtle.importKey('raw', key, {name: 'HMAC', hash: 'SHA-256'},
                                               false, ['sign']);
    let sign = await crypto.subtle.sign({name: 'HMAC'}, wc_key, s);

    return s + '.' + Buffer.from(sign).toString('base64url');
}

async function jwt(r) {
    let claims = {
        iss: "nginx",
        sub: "alice",
        foo: 123,
        bar: "qq",
        zyx: false
    };

    let jwtv = await generate_hs256_jwt(claims, process.env.JWT_GEN_KEY, 600);
    r.setReturnValue(jwtv);
}

export default {jwt};
