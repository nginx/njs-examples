function join(r) {
        join_subrequests(r, ['/foo', '/bar']);
}

function join_subrequests(r, subs) {
    var parts = [];

    function done(reply) {
        parts.push({ uri:  reply.uri,
                     code: reply.status,
                     body: reply.responseBody });

        if (parts.length == subs.length) {
            r.return(200, JSON.stringify(parts));
        }
    }

    for (var i in subs) {
        r.subrequest(subs[i], done);
    }
}

export default {join}
