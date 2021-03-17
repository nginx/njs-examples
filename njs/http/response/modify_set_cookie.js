function cookies_filter(r) {
    var cookies = r.headersOut['Set-Cookie'];
    r.headersOut['Set-Cookie'] = cookies.filter(v=>v.length > Number(r.args.len));
}

export default {cookies_filter};
