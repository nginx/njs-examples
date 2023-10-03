async function process(r) {
    try {
        let reply = await r.subrequest('/auth')
        let response = JSON.parse((reply.responseText));
        let token = response['token'];

        if (!token) {
            throw new Error("token is not available");
        }

        let backend_reply = await r.subrequest('/backend', `token=${token}`);
        r.return(backend_reply.status, backend_reply.responseText);

    } catch (e) {
        r.return(500, e);
    }
}

function authenticate(r) {
    let auth = r.headersIn.Authorization;
    if (auth && auth.slice(7) === 'secret') {
        r.return(200, JSON.stringify({status: "OK", token:42}));
        return;
    }

    r.return(403, JSON.stringify({status: "INVALID"}));
}

export default {process, authenticate};
