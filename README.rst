=========================
NGINX JavaScript examples
=========================

.. contents::
   :depth: 3

Intro
=====

This repo contains complete examples for various use cases where `njs <http://nginx.org/en/docs/njs/>`_ is useful. The document as well as `njs documentation <http://nginx.org/en/docs/njs/>`_ expects some familiarity with and understanding of nginx. Beginners should refer to the official `admin guide <https://docs.nginx.com/nginx/admin-guide/>`_.

Note: the examples below work with njs >= `0.5.2 <http://nginx.org/en/docs/njs/changes.html#njs0.5.2>`_. To see the current version run the following command: ``docker run -i -t nginx:latest /usr/bin/njs -V``.

Running inside Docker
---------------------

.. code-block:: shell

  git clone https://github.com/xeioex/njs-examples
  cd njs-examples
  EXAMPLE='http/hello'
  docker run --rm --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro -v $(pwd)/njs/:/etc/nginx/njs/:ro -p 80:80 -p 443:443 -d nginx

  # Stopping.
  docker stop njs_example

Status
------
While njs is in active development it is production ready. Its reliability has been proven by extensive test coverage as well as a good track record with our customers.

nginx compatibility
-------------------
As njs is a `native nginx module <http://nginx.org/en/docs/dev/development_guide.html#Modules>`_ its compatibility with nginx is high. While it is developed as a separate project, it is routinely tested with latest nginx versions on various platforms and architectures.

Presentation at nginx.conf 2018
-------------------------------
https://youtu.be/Jc_L6UffFOs

Installation
------------
njs is available as a part of official nginx docker image as well as an officially supported `packet <http://nginx.org/en/linux_packages.html>`_ for major linux distributions.

Repository
----------
Please ask questions, report issues, and send patches via official `Github mirror <https://github.com/nginx/njs>`_.

HTTP
====

Hello world example [http/hello]
--------------------------------

nginx.conf:

.. code-block:: nginx

  load_module modules/ngx_http_js_module.so;

  events {}

  http {
    js_path "/etc/nginx/njs/";

    js_import utils.js;
    js_import main from http/hello.js;

    server {
      listen 80;

      location = /version {
         js_content utils.version;
      }

      location / {
        js_content main.hello;
      }
   }
 }

example.js:

.. code-block:: js

  function hello(r) {
    r.return(200, "Hello world!\n");
  }

  export default {hello}

Checking:

.. code-block:: shell

  curl http://localhost/
  Hello world!

  curl http://localhost/version
  0.4.1

Authorization
-------------

Getting arbitrary field from JWT as a nginx variable [http/authorization/jwt]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx.conf:

.. code-block:: nginx

  http {
    js_path "/etc/nginx/njs/";

    js_import utils.js;
    js_import main from http/authorization/jwt.js;

    js_set $jwt_payload_sub main.jwt_payload_sub;

    server {
  ...
        location /jwt {
            return 200 $jwt_payload_sub;
        }
    }
  }

example.js:

.. code-block:: js

    function jwt(data) {
        var parts = data.split('.').slice(0,2)
            .map(v=>Buffer.from(v, 'base64url').toString())
            .map(JSON.parse);
        return { headers:parts[0], payload: parts[1] };
    }

    function jwt_payload_sub(r) {
        return jwt(r.headersIn.Authorization.slice(7)).payload.sub;
    }

    export default {jwt_payload_sub}

Checking:

.. code-block:: shell

  curl 'http://localhost/jwt' -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImV4cCI6MTU4NDcyMzA4NX0.eyJpc3MiOiJuZ2lueCIsInN1YiI6ImFsaWNlIiwiZm9vIjoxMjMsImJhciI6InFxIiwienl4IjpmYWxzZX0.Kftl23Rvv9dIso1RuZ8uHaJ83BkKmMtTwch09rJtwgk"
  alice

Generating JWT token [http/authorization/gen_hs_jwt]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx.conf:

.. code-block:: nginx

  env JWT_GEN_KEY;

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import utils.js;
    js_import main from http/authorization/gen_hs_jwt.js;

    js_set $jwt main.jwt;

    server {
  ...
        location /jwt {
            return 200 $jwt;
        }
    }
  }

example.js:

.. code-block:: js

    function generate_hs256_jwt(claims, key, valid) {
        var header = { typ: "JWT",  alg: "HS256" };
        var claims = Object.assign(claims, {exp: Math.floor(Date.now()/1000) + valid});

        var s = [header, claims].map(JSON.stringify)
                                .map(v=>v.toString('base64url'))
                                .join('.');

        var h = require('crypto').createHmac('sha256', key);

        return s + '.' + h.update(s).digest('base64url');
    }

    function jwt(r) {
        var claims = {
            iss: "nginx",
            sub: "alice",
            foo: 123,
            bar: "qq",
            zyx: false
        };

        return generate_hs256_jwt(claims, process.env.JWT_GEN_KEY, 600);
    }

    export default {jwt}

Checking:

.. code-block:: shell

  docker run --rm --name njs_example -e JWT_GEN_KEY="foo" ...

  curl 'http://localhost/jwt'
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImV4cCI6MTU4NDcyMjk2MH0.eyJpc3MiOiJuZ2lueCIsInN1YiI6ImFsaWNlIiwiZm9vIjoxMjMsImJhciI6InFxIiwienl4IjpmYWxzZX0.GxfKkJSWI4oq5sGBg4aKRAcFeKmiA6v4TR43HbcP2X8


Secure link [http/authorization/secure_link_hash]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Protecting ``/secure/`` location from simple bots and web crawlers.

nginx.conf:

.. code-block:: nginx

  env SECRET_KEY;

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import main from http/authorization/secure_link_hash.js;

    js_set $new_foo main.create_secure_link;
    js_set $secret_key key main.secret_key;

    server {
          listen 80;

          ...

          location /secure/ {
              error_page 403 = @login;

              secure_link $cookie_foo;
              secure_link_md5 "$uri$secret_key";

              if ($secure_link = "") {
                      return 403;
              }

              proxy_pass http://localhost:8080;
          }

          location @login {
              add_header Set-Cookie "foo=$new_foo; Max-Age=60";
              return 302 $request_uri;
          }
      }
  }

example.js:

.. code-block:: js

  function secret_key(r) {
      return process.env.SECRET_KEY;
  }

  function create_secure_link(r) {
      return require('crypto').createHash('md5')
                              .update(r.uri).update(process.env.SECRET_KEY)
                              .digest('base64url');
  }

  export default {secret_key, create_secure_link}

Checking:

.. code-block:: shell

  docker run --rm --name njs_example -e SECRET_KEY=" mykey" ...

  curl http://127.0.0.1/secure/r
  302

  curl http://127.0.0.1/secure/r -L
  curl: (47) Maximum (50) redirects followed

  curl http://127.0.0.1/secure/r --cookie-jar cookie.txt
  302

  curl http://127.0.0.1/secure/r --cookie cookie.txt
  PASSED

Authorizing requests using auth_request [http/authorization/auth_request]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _`auth request`:

`auth_request <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`_
is generic nginx modules which implements client authorization based on the result of a subrequest.
Combination of auth_request and njs allows to implement arbitrary authorization logic.

nginx.conf:

.. code-block:: nginx

    ...

    env SECRET_KEY;

    http {
      js_path "/etc/nginx/njs/";

      js_import main from http/authorization/auth_request.js;

      upstream backend {
          server 127.0.0.1:8081;
      }

      server {
          listen 80;

          location /secure/ {
              auth_request /validate;

              proxy_pass http://backend;
          }

          location /validate {
              internal;
              js_content main.authorize;
          }
      }

      server {
          listen 127.0.0.1:8081;
          return 200 "BACKEND:$uri\n";
      }
    }

example.js:

.. code-block:: js

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

Checking:

.. code-block:: shell

  docker run --rm --name njs_example -e SECRET_KEY="foo" ...

  curl http://localhost/secure/B
  <html>
  <head><title>401 Authorization Required</title></head>
  <body>
  <center><h1>401 Authorization Required</h1></center>
  <hr><center>nginx/1.19.0</center>
  </body>
  </html>

  curl http://localhost/secure/B  -H Signature:fk9WRmw7Rl+NwVAA759+H2Uq
  <html>
  <head><title>401 Authorization Required</title></head>
  <body>
  <center><h1>401 Authorization Required</h1></center>
  <hr><center>nginx/1.19.0</center>
  </body>
  </html>

  curl http://localhost/secure/B  -H Signature:fk9WRmw7Rl+NwVAA759+H2UqxNs=
  BACKEND:/secure/B

  docker logs njs_example
  172.17.0.1 - - [03/Aug/2020:18:22:30 +0000] "GET /secure/B HTTP/1.1" 401 179 "-" "curl/7.58.0"
  2020/08/03 18:22:47 [error] 28#28: *3 js: No signature
  172.17.0.1 - - [03/Aug/2020:18:22:47 +0000] "GET /secure/B HTTP/1.1" 401 179 "-" "curl/7.58.0"
  2020/08/03 18:22:54 [error] 28#28: *4 js: Invalid signature: fk9WRmw7Rl+NwVAA759+H2UqxNs=

  172.17.0.1 - - [03/Aug/2020:18:22:54 +0000] "GET /secure/B HTTP/1.1" 401 179 "-" "curl/7.58.0"
  127.0.0.1 - - [03/Aug/2020:18:23:00 +0000] "GET /secure/B HTTP/1.0" 200 18 "-" "curl/7.58.0"
  172.17.0.1 - - [03/Aug/2020:18:23:00 +0000] "GET /secure/B HTTP/1.1" 200 18 "-" "curl/7.58.0"

Authorizing requests based on request body content [http/authorization/request_body]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
`Authorizing requests using auth_request [http/authorization/auth_request]`_ cannot inspect client request body.
Sometimes inspecting client request body is required, for example to validate POST arguments (application/x-www-form-urlencoded).

nginx.conf:

.. code-block:: nginx

    ...

    env SECRET_KEY;

    http {
      js_path "/etc/nginx/njs/";

      js_import main from http/authorization/request_body.js;

      upstream backend {
          server 127.0.0.1:8081;
      }

      server {
          listen 80;

          location /secure/ {
              js_content main.authorize;
          }

          location @app-backend {
              proxy_pass http://backend;
          }
      }

      server {
          listen 127.0.0.1:8081;
          return 200 "BACKEND:$uri\n";
      }
    }

example.js:

.. code-block:: js

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
            var body  = r.requestBody;
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

Checking:

.. code-block:: shell

  docker run --rm --name njs_example -e SECRET_KEY="foo" ...

  curl http://localhost/secure/B
  No signature

  curl http://localhost/secure/B?a=1 -H Signature:A
  Invalid signature: YC5iL6aKDnv7XOjknEeDL+P58iw=

  curl http://localhost/secure/B?a=1 -H Signature:YC5iL6aKDnv7XOjknEeDL+P58iw=
  BACKEND:/secure/B

  curl http://localhost/secure/B -d "a=1" -X POST -H Signature:YC5iL6aKDnv7XOjknEeDL+P58iw=
  BACKEND:/secure/B

Certificates
------------

Reading subject alternative from client certificate [http/certs/subject_alternative]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Accessing arbitrary fields in client certificates.

nginx.conf:

Certificates are created using the following `guide <https://jamielinux.com/docs/openssl-certificate-authority/introduction.html>`_.

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import main from http/certs/js/subject_alternative.js;

    js_set $san main.san;

    server {
          listen 443 ssl;

          server_name www.example.com;

          ssl_password_file /etc/nginx/njs/http/certs/ca/password;
          ssl_certificate /etc/nginx/njs/http/certs/ca/intermediate/certs/www.example.com.cert.pem;
          ssl_certificate_key /etc/nginx/njs/http/certs/ca/intermediate/private/www.example.com.key.pem;

          ssl_client_certificate /etc/nginx/njs/http/certs/ca/intermediate/certs/ca-chain.cert.pem;
          ssl_verify_client on;

          location / {
              return 200 $san;
          }
    }
  }

example.js:

.. code-block:: js

    import x509 from 'x509.js';

    function san(r) {
        var pem_cert = r.variables.ssl_client_raw_cert;
        if (!pem_cert) {
            return '{"error": "no client certificate"}';
        }

        var cert = x509.parse_pem_cert(pem_cert);

        // subjectAltName oid 2.5.29.17
        return JSON.stringify(x509.get_oid_value(cert, "2.5.29.17")[0]);
    }

    export default {san};

Checking:

.. code-block:: shell

  openssl x509 -noout -text -in njs/http/certs/ca/intermediate/certs/client.cert.pem | grep 'X509v3 Subject Alternative Name' -A1
  X509v3 Subject Alternative Name:
  IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1, DNS:example.com, DNS:www2.example.com

  curl https://localhost/ --insecure --key njs/http/certs/ca/intermediate/private/client.key.pem --cert njs/http/certs/ca/intermediate/certs/client.cert.pem  --pass secretpassword
  ["7f000001","00000000000000000000000000000001","example.com","www2.example.com"]

Proxying
--------

Subrequests join [http/join_subrequests]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Combining the results of several subrequests asynchronously into a single JSON reply.

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import utils.js;
    js_import main from http/join_subrequests.js;

    server {
          listen 80;

          location /join {
              js_content main.join;
          }

          location /foo {
              proxy_pass http://localhost:8080;
          }

          location /bar {
              proxy_pass http://localhost:8090;
          }
    }
 }

example.js:

.. code-block:: js

  function join(r) {
      join_subrequests(r, ['/foo', '/bar']);
  }

  function join_subrequests(r, subs) {
      var parts = [];

      function done(reply) {
          parts.push({ uri:  reply.uri,
                       code: reply.status,
                       body: reply.responseBody });

          if (parts.length == subs.length) {
              r.return(200, JSON.stringify(parts));
          }
      }

      for (var i in subs) {
          r.subrequest(subs[i], done);
      }
  }

  export default {join}

Checking:

.. code-block:: shell

  curl http://localhost/join
  [{"uri":"/foo","code":200,"body":"FOO"},{"uri":"/bar","code":200,"body":"BAR"}]


Subrequests chaining [http/subrequests_chaining]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Subrequests chaining using JS promises.

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import utils.js;
    js_import main from http/subrequests_chaining.js;

    server {
          listen 80;

          location / {
              js_content main.process;
          }

          location = /auth {
              internal;
              proxy_pass http://localhost:8080;
          }

          location = /backend {
              internal;
              proxy_pass http://localhost:8090;
          }
    }

    ...
 }

example.js:

.. code-block:: js

    function process(r) {
        r.subrequest('/auth')
            .then(reply => JSON.parse(reply.responseBody))
            .then(response => {
                if (!response['token']) {
                    throw new Error("token is not available");
                }
                return response['token'];
            })
        .then(token => {
            r.subrequest('/backend', `token=${token}`)
                .then(reply => r.return(reply.status, reply.responseBody));
        })
        .catch(e => r.return(500, e));
    }

    function authenticate(r) {
        if (r.headersIn.Authorization.slice(7) === 'secret') {
            r.return(200, JSON.stringify({status: "OK", token:42}));
            return;
        }

        r.return(403, JSON.stringify({status: "INVALID"}));
    }

    export default {process, authenticate}

Checking:

.. code-block:: shell

  curl http://localhost/start -H 'Authorization: Bearer secret'
  Token is 42

  curl http://localhost/start
  SyntaxError: Unexpected token at position 0
  at JSON.parse (native)
  at anonymous (example.js:3)
  at native (native)
  at main (native)

  curl http://localhost/start -H 'Authorization: Bearer secre'
  Error: token is not available
  at anonymous (example.js:4)
  at native (native)
  at main (native)

Modifying response
------------------

Modifying or deleting cookies sent by the upstream server [http/response/modify_set_cookie]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import main from http/response/modify_set_cookie.js;

    server {
          listen 80;

          location /modify_cookies {
              js_header_filter main.cookies_filter;
              proxy_pass http://localhost:8080;
          }
    }

    server {
          listen 8080;

          location /modify_cookies {
              add_header Set-Cookie "XXXXXX";
              add_header Set-Cookie "BB";
              add_header Set-Cookie "YYYYYYY";
              return 200;
          }
    }
  }

example.js:

.. code-block:: js

    function cookies_filter(r) {
        var cookies = r.headersOut['Set-Cookie'];
        r.headersOut['Set-Cookie'] = cookies.filter(v=>v.length > Number(r.args.len));
    }

    export default {cookies_filter};

Checking:

.. code-block:: shell

  curl http://localhost/modify_cookies?len=1 -v
    ...
  < Set-Cookie: XXXXXX
  < Set-Cookie: BB
  < Set-Cookie: YYYYYYY

  curl http://localhost/modify_cookies?len=3 -v
    ...
  < Set-Cookie: XXXXXX
  < Set-Cookie: YYYYYYY

Converting response body characters to lower case [http/response/to_lower_case]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import main from http/response/to_lower_case.js;

    server {
          listen 80;

          location / {
              js_body_filter main.to_lower_case;
              proxy_pass http://localhost:8080;
          }
    }

    server {
          listen 8080;

          location / {
              return 200 'Hello World';
          }
    }
  }

example.js:

.. code-block:: js

    function to_lower_case(r, data, flags) {
        r.sendBuffer(data.toLowerCase(), flags);
    }

    export default {to_lower_case};

Checking:

.. code-block:: shell

  curl http://localhost/
  hello world

Stream
======

Authorization
-------------

Authorizing connections using ngx.fetch() as auth_request [stream/auth_request]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The example illustrates the usage of ngx.fetch() as an `auth request`_ analog in
stream with a very simple TCP-based protocol: a connection starts with a
magic prefix "MAGiK" followed by a secret 2 bytes. The preread_verify handler
reads the first part of a connection and sends the secret bytes for verification
to a HTTP endpoint. Later it decides based upon the endpoint reply whether
forward the connection to an upstream or reject the connection.

nginx.conf:

.. code-block:: nginx

  stream {
        js_path "/etc/nginx/njs/";

        js_import main from stream/auth_request.js;

        server {
              listen 80;

              js_preread  main.preread_verify;

              proxy_pass 127.0.0.1:8081;
        }

        server {
              listen 8081;

              return BACKEND\n;
        }
  }

  http {
        js_path "/etc/nginx/njs/";

        js_import main from stream/auth_request.js;

        server {
              listen 8080;

              server_name  aaa;

              location /validate {
                  js_content main.validate;
              }
        }
  }

example.js:

.. code-block:: js

  function preread_verify(s) {
      var collect = '';

      s.on('upload', function (data, flags) {
          collect += data;

          if (collect.length >= 5 && collect.startsWith('MAGiK')) {
              s.off('upload');
              ngx.fetch('http://127.0.0.1:8080/validate',
                        {body: collect.slice(5,7), headers: {Host:'aaa'}})
              .then(reply => (reply.status == 200) ? s.done(): s.deny())

          } else if (collect.length) {
              s.deny();
          }
      });
  }

  function validate(r) {
          r.return((r.requestText == 'QZ') ? 200 : 403);
  }

  export default {validate, preread_verify};

Checking:

.. code-block:: shell

  telnet 127.0.0.1 80
  ...
  Hi
  Connection closed by foreign host.

  telnet 127.0.0.1 80
  ...
  MAGiKQZ
  BACKEND
  Connection closed by foreign host.

  telnet 127.0.0.1 80
  ...
  MAGiKQQ
  Connection closed by foreign host.

Routing
-------

Choosing upstream in stream based on the underlying protocol [stream/detect_http]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx.conf:

.. code-block:: nginx

  ...

  stream {
    js_path "/etc/nginx/njs/";

    js_import utils.js;
    js_import main from stream/detect_http.js;

    js_set $upstream main.upstream_type;

    upstream httpback {
        server 127.0.0.1:8080;
    }

    upstream tcpback {
        server 127.0.0.1:3001;
    }

    server {
          listen 80;

          js_preread  main.detect_http;

          proxy_pass $upstream;
    }
  }


example.js:

.. code-block:: js

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

Checking:

.. code-block:: shell

  curl http://localhost/
  HTTPBACK

  telnet 127.0.0.1 80
  Trying 127.0.0.1...
  Connected to 127.0.0.1.
  Escape character is '^]'.
  TEST
  TCPBACK
  Connection closed by foreign host.

Misc
====

File IO [misc/file_io]
----------------------

nginx.conf:

.. code-block:: nginx

    http {
      js_path "/etc/nginx/njs/";

      js_import utils.js;
      js_import main from misc/file_io.js;

      server {
            listen 80;

            location /version {
                js_content utils.version;
            }

            location /push {
                js_content main.push;
            }

            location /flush {
                js_content main.flush;
            }

            location /read {
                js_content main.read;
            }
    }

example.js:

.. code-block:: js

  var fs = require('fs');
  var STORAGE = "/tmp/njs_storage"

  function push(r) {
          fs.appendFileSync(STORAGE, r.requestBody);
          r.return(200);
  }

  function flush(r) {
          fs.writeFileSync(STORAGE, "");
          r.return(200);
  }

  function read(r) {
          var data = "";
          try {
              data = fs.readFileSync(STORAGE);
          } catch (e) {
          }

          r.return(200, data);
  }

  export default {push, flush, read}

.. code-block:: shell

  curl http://localhost/read
  200 <empty reply>

  curl http://localhost/push -X POST --data 'AAA'
  200

  curl http://localhost/push -X POST --data 'BBB'
  200

  curl http://localhost/push -X POST --data 'CCC'
  200

  curl http://localhost/read
  200 AAABBBCCC

  curl http://localhost/flush -X POST
  200

  curl http://localhost/read
  200 <empty reply>

Command line interface
======================

.. code-block:: shell

  docker run -i -t nginx:latest /usr/bin/njs

.. code-block:: none

    interactive njs 0.4.1

    v.<Tab> -> the properties and prototype methods of v.

    >> globalThis
    global {
     console: Console {
      log: [Function: native],
      dump: [Function: native],
      time: [Function: native],
      timeEnd: [Function: native]
     },
     njs: njs {
      version: '0.4.1'
     },
     print: [Function: native],
     global: [Circular],
     process: process {
      argv: [
       '/usr/bin/njs',
       ''
      ],
      env: {
       HOSTNAME: '483ac20bb33f',
       HOME: '/root',
       PKG_RELEASE: '1~buster',
       TERM: 'xterm',
       NGINX_VERSION: '1.19.0',
       PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       NJS_VERSION: '0.4.1',
       PWD: '/'
      }
     }
    }

Additional learning materials
=============================

`soulteary/njs-learning-materials <https://github.com/soulteary/njs-learning-materials>`_
