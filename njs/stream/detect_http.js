var is_http = 0;

function detect_http(s) {
    s.on('upload', function (data, flags) {
        var n = data.indexOf('\r\n');
        if (n != -1 && data.substr(0, n - 1).endsWith(" HTTP/1.")) {
            is_http = 1;
        }

        if (data.length || flags.last) {
            s.done();
        }
    });
}

function upstream_type(s) {
    return is_http ? "httpback" : "tcpback";
}

export default {detect_http, upstream_type}
