// Injecting HTTP header using stream proxy

function inject_foo_header(s) {
    inject_header(s, 'Foo: my_foo');
}

function inject_header(s, header) {
    var req = '';

    s.on('upload', function(data, flags) {
        req += data;
        var n = req.search('\n');
        if (n != -1) {
            var rest = req.substr(n + 1);
            req = req.substr(0, n + 1);
            s.send(req + header + '\r\n' + rest, flags);
            s.off('upload');
        }
    });
}

export default {inject_foo_header}
