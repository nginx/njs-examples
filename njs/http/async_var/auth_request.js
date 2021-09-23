import qs from "querystring";

function choose_upstream(r) {
    let backend;
    let args = qs.parse(r.headersIn['X-Original-URI'].split('?')[1]);

    switch (args.token) {
    case 'A':
        backend = '127.0.0.1:8081';
        break;
    case 'B':
        backend = '127.0.0.1:8082';
        break;
    default:
        r.return(404);
    }

    r.headersOut['X-backend'] = backend;
    r.return(200);
}

export default {choose_upstream}
