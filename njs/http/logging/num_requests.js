function num_requests(r) {
    var n = r.variables.foo;
    n = n ? Number(n) + 1 : 1;
    r.variables.foo = n;
    return n;
}

export default {num_requests};
