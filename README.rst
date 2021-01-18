=========================
NGINX JavaScript examples
=========================

****************
Table of content
****************

- Intro_
- HTTP_

  - Authorization_
  - Proxying_
- Stream_

  - Routing_
- Misc_
- `Command line interface`_

Intro
=====

Note: the examples below work with njs >= `0.4.0 <http://nginx.org/en/docs/njs/changes.html#njs0.4.0>`_, see `this version <https://github.com/xeioex/njs-examples/tree/b1c992c742b5d41dea2e087ebea98e098543a341>`_ for older releases.

Running inside Docker:

.. code-block:: shell

  git clone https://github.com/xeioex/njs-examples
  cd njs-examples
  EXAMPLE='http/hello'
  docker run --rm --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro  -v $(pwd)/njs/$EXAMPLE.js:/etc/nginx/example.js:ro -v $(pwd)/njs/utils.js:/etc/nginx/utils.js:ro -p 80:80 -p 8090:8090 -d nginx

  # Stopping.
  docker stop njs_example

Hello world [http/hello]
-----------------------

nginx.conf:

.. code-block:: nginx

  load_module modules/ngx_http_js_module.so;

  events {}

  http {
    js_import utils.js;
    js_import main from example.js;

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

HTTP
====

Authorization
=============

Getting arbitrary field from JWT as a nginx variable [http/authorization/jwt]
----------------------------------------------------------------------------

nginx.conf:

.. code-block:: nginx

  http {
    js_import utils.js;
    js_import main from example.js;

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
---------------------------------------------------

nginx.conf:

.. code-block:: nginx

  env JWT_GEN_KEY;

  ...

  http {
    js_import utils.js;
    js_import main from example.js;

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


Secure hash [http/authorization/secure_link_hash]
-------------------------------------------------
Protecting ``/secure/`` location from simple bots and web crawlers.

nginx.conf:

.. code-block:: nginx

  env SECRET_KEY;

  ...

  http {
    js_import main from example.js;

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

  docker run --rm --name njs_example -e JWT_GEN_KEY=" mykey" ...

  curl http://127.0.0.1/secure/r
  302

  curl http://127.0.0.1/secure/r -L
  curl: (47) Maximum (50) redirects followed

  curl http://127.0.0.1/secure/r --cookie-jar cookie.txt
  302

  curl http://127.0.0.1/secure/r --cookie cookie.txt
  PASSED

Authorizing requests using auth_request [http/authorization/auth_request]
-------------------------------------------------------------------------
`auth_request <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`_
is generic nginx modules which implements client authorization based on the result of a subrequest.
Combination of auth_request and njs allows to implement arbitrary authorization logic.

nginx.conf:

.. code-block:: nginx

    ...

    env SECRET_KEY;

    http {
          js_import main from example.js;

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
-----------------------------------------------------------------------------------
`Authorizing requests using auth_request [http/authorization/auth_request]`_ cannot inspect client request body.
Sometimes inspecting client request body is required, for example to validate POST arguments (application/x-www-form-urlencoded).

nginx.conf:

.. code-block:: nginx

    ...

    env SECRET_KEY;

    http {
          js_import main from example.js;

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

Proxying
========

Subrequests join [http/join_subrequests]
----------------------------------------
Combining the results of several subrequests asynchronously into a single JSON reply.

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_import utils.js;
    js_import main from example.js;

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
-------------------------------------------
Subrequests chaining using JS promises.

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_import utils.js;
    js_import main from example.js;

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


Stream
======

Routing
=======

Choosing upstream in stream based on the underlying protocol [stream/detect_http]
---------------------------------------------------------------------------------

nginx.conf:

.. code-block:: nginx

  ...

  stream {
    js_import utils.js;
    js_import main from example.js;

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

  echo 'ABC' | nc 127.0.0.1 80 -q1
  TCPBACK

Misc
====

File IO [misc/file_io]
----------------------

nginx.conf:

.. code-block:: nginx

    http {
      js_import utils.js;
      js_import main from example.js;

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
