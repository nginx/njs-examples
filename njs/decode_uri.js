function version(r) {
    r.return(200, njs.version);
}

function dec_foo(r) {
    return decodeURIComponent(r.args.foo);
}
