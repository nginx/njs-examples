async function set_keyval(r) {
    let method = r.args.method ? r.args.method : 'POST'; 
    let res = await r.subrequest('/api/7/http/keyvals/foo',
                                 {method, body: r.requestBody});

    if (res.status >= 300) {
        r.return(res.status, res.responseBody);
        return;
    }

    r.return(200);
}

export default {set_keyval};
