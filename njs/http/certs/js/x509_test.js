import fs from 'fs';
import x509 from 'x509.js';

function compareArray(a, b) {
    if (b.length !== a.length) {
        return false;
    }

    for (var i = 0; i < a.length; i++) {
        if (!compareArray.isSameValue(b[i], a[i])) {
            console.log(`FAILED at ${i} ${b[i]} != ${a[i]}`)
            return false;
        }
    }

    return true;
}

compareArray.isSameValue = function(a, b) {
    if (a === 0 && b === 0) return 1 / a === 1 / b;
    if (a !== a && b !== b) return true;

    return a === b;
}

function run(t) {
    for (let i = 0; i < t.length; i++) {
        let result = t[i].method(t[i].buf)[0];
        if (!compareArray(result, t[i].expected)) {
            throw `${t[i].name} failed`;
        }

        console.log(`${t[i].name} passed`);
    }

    console.log("tests PASSED");
}

/*
 * # generate test.der
 * python3 asn1_gen.py > test.der
 * # verify output
 * openssl asn1parse -inform DER -dump -in test.der -dump
 * # run tests
 * njs x509_test.js
 */

let test_der = fs.readFileSync('test.der');
let client_cert = fs.readFileSync('../ca/intermediate/certs/client.cert.pem', 'utf8');

run([
    { name: 'test.der', buf: test_der, method: x509.asn1_read, 
      expected: [0,-137878,'029c0b3400977a9bdf97','printable string','is5 string','αβγδ','9','4f2606']},
    { name: 'client.cert.pem', buf: client_cert,
      method: (pem) => {
          let cert = x509.parse_pem_cert(pem);
          return x509.get_oid_value(cert, "2.5.29.17");
      }, 
      expected: ['7f000001','00000000000000000000000000000001','example.com','www2.example.com']}
])

console.log('benchmark')

console.time('test.der 100000x')
for (var i = 0; i < 100000; i++) {
    x509.asn1_read(test_der);
}
console.timeEnd('test.der 100000x')

console.time('client.cert.pem 1000x')
for (var i = 0; i < 1000; i++) {
    x509.parse_pem_cert(client_cert);
}
console.timeEnd('client.cert.pem 1000x')
