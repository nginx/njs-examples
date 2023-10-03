function authorize(r) {
    var signature = r.headersIn.Signature;

    if (!signature) {
        r.return(401, "No signature\n");
        return;
    }

    var h = require('crypto').createHmac('sha1', process.env.SECRET_KEY);

    h.update(r.uri);

    switch (r.method) {
    case 'GET':
        var args = r.variables.args;
        h.update(args ? args : "");
        break;

    case 'POST':
        var body  = r.requestText;
        if (r.headersIn['Content-Type'] != 'application/x-www-form-urlencoded'
            || !body.length)
        {
            r.return(401, "Unsupported method\n");
        }

        h.update(body);
        break;

    default:
        r.return(401, "Unsupported method\n");
        return;
    }

    var req_sig = h.digest("base64");

    if (req_sig != signature) {
        r.return(401, `Invalid signature: ${req_sig}\n`);
        return;
    }

    r.internalRedirect('@app-backend');
}

export default {authorize}
