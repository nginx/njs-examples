function process(r) {
    r.subrequest('/auth')
        .then(reply => JSON.parse(reply.responseBody))
        .then(response => {
            if (!response['token']) {
                throw new Error("token is not available");
            }
            return response['token'];
        })
    .then(token => {
        r.subrequest('/backend', `token=${token}`)
            .then(reply => r.return(reply.status, reply.responseBody));
    })
    .catch(e => r.return(500, e));
}

function authenticate(r) {
    if (r.headersIn.Authorization.slice(7) === 'secret') {
        r.return(200, JSON.stringify({status: "OK", token:42}));
        return;
    }

    r.return(403, JSON.stringify({status: "INVALID"}));
}

export default {process, authenticate}
