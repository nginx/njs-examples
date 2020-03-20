function version(r) {
    r.return(200, njs.version);
}

function jwt(data) {
    var parts = data.split('.').slice(0,2)
        .map(v=>String.bytesFrom(v, 'base64url'))
        .map(JSON.parse);
    return { headers:parts[0], payload: parts[1] };
}

function jwt_payload_sub(r) {
    return jwt(r.headersIn.Authorization.slice(7)).payload.sub;
}
