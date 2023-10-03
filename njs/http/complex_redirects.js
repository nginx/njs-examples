var fs = require("fs");
var DB = "/tmp/njs_resolv.db";

function open_db() {
    var data, map;

    try {
        data = fs.readFileSync(DB);
    } catch (e) {
        data = "{}";
    }

    try {
        map = JSON.parse(data);
    } catch (e) {
        throw Error("open_db: " + e);
    }

    return map;
}

function commit_db(map) {
    var ret = 200;

    try {
        fs.writeFileSync(DB, JSON.stringify(map));
    } catch (e) {
        ret = 500;
    }

    return ret;
}

function map(r) {
    try {
        r.return(200, JSON.stringify(open_db()));
    } catch (e) {
        r.return(500, "map: " + e);
    }
}

function resolv(r) {
    try {
        var map = open_db();
        var uri = r.variables.request_uri.split("?")[0];
        var mapped_uri = map[uri];

        r.headersOut['Route'] = mapped_uri ? mapped_uri : uri;
        r.return(200);

    } catch (e) {
        r.return(500, "resolv: " + e);
    }
}

function add(r) {
    try {
        var map = open_db();
        var body = r.requestText;

        if (!body) {
            r.return(400, "request is empty");
            return;
        }

        var pair = JSON.parse(body);
        if (!pair.from || !pair.to) {
            r.return(400, "invalid request: expected format: {\"from\": \"/uri\", \"to\": \"/mapped_uri\"} ");
            return;
        }

        map[pair.from] = pair.to;

        r.return(commit_db(map));

    } catch (e) {
        r.return(500, "add: " + e);
    }
}

function remove(r) {
    try {
        var map = open_db();
        var body = r.requestText;

        if (!body) {
            r.return(400, "request is empty");
            return;
        }

        var pair = JSON.parse(body);
        if (!pair.from) {
            r.return(400, "invalid request: expected format: { \"from\": \"/uri\"} ");
            return;
        }

        delete map[pair.from];

        r.return(commit_db(map));

    } catch (e) {
        r.return(500, "remove: " + e);
    }
}

export default {add, resolv, map, remove};
