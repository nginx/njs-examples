async function join(r) {
    join_subrequests(r, ['/foo', '/bar']);
}

async function join_subrequests(r, subs) {
    let results = await Promise.all(subs.map(uri => r.subrequest(uri)));

    let response = results.map(reply => ({
        uri:  reply.uri,
        code: reply.status,
        body: reply.responseText,
    }));

    r.return(200, JSON.stringify(response));
}

export default {join};
