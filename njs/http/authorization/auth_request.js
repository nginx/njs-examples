function authorize(r) {
    var signature = r.headersIn.Signature;

    if (!signature) {
        r.error("No signature");
        r.return(401);
        return;
    }

    if (r.method != 'GET') {
        r.error(`Unsupported method: ${r.method}`);
        r.return(401);
        return;
    }

    var args = r.variables.args;

    var h = require('crypto').createHmac('sha1', process.env.SECRET_KEY);

    h.update(r.uri).update(args ? args : "");

    var req_sig = h.digest("base64");

    if (req_sig != signature) {
        r.error(`Invalid signature: ${req_sig}\n`);
        r.return(401);
        return;
    }

    r.return(200);
}

export default {authorize}
