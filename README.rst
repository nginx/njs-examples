=================
NGINX JavaScript examples
=================


Examples
********

Running inside Docker:

.. code-block:: shell

  git clone https://github.com/xeioex/njs-examples
  cd njs-examples
  EXAMPLE='hello'
  docker run --rm --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro  -v $(pwd)/njs/$EXAMPLE.js:/etc/nginx/example.js:ro -p 80:80 -p 8090:8090 -d nginx

  # Stopping.
  docker stop njs_example

Hello world [hello]
===========

nginx.conf:

.. code-block:: nginx

  load_module modules/ngx_http_js_module.so;

  events {}

  http {
    js_include example.js;

    server {
      listen 80;

      location /version {
         js_content version;
      }

      location /hello {
        js_content hello;
      }
   }
 }

example.js:

.. code-block:: js

  function version(r) {
    r.return(200, njs.version);
  }

  function hello(r) {
    r.return(200, "Hello world!\n");
  }

Checking:

.. code-block:: shell

  curl http://localhost/hello
  Hello world!

  curl http://localhost/version
  0.2.4

Getting arbitrary field from JWT as a nginx variable [jwt]
===========

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.js;

      js_set $jwt_payload_sub jwt_payload_sub;

      server {
  ...
            location /jwt {
                return 200 $jwt_payload_name;
            }
      }
  }

example.js:

.. code-block:: js

    function jwt(data) {
        var parts = data.split('.').slice(0,2)
            .map(v=>String.bytesFrom(v, 'base64url'))
            .map(JSON.parse);
        return { headers:parts[0], payload: parts[1] };
    }

    function jwt_payload_sub(r) {
        return jwt(r.headersIn.Authorization.slice(7)).payload.sub;
    }

Checking:

.. code-block:: shell

  curl 'http://localhost/jwt' -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImV4cCI6MTU4NDcyMzA4NX0.eyJpc3MiOiJuZ2lueCIsInN1YiI6ImFsaWNlIiwiZm9vIjoxMjMsImJhciI6InFxIiwienl4IjpmYWxzZX0.Kftl23Rvv9dIso1RuZ8uHaJ83BkKmMtTwch09rJtwgk"
  alice

Generating JWT token [gen_hs_jwt]
===========

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.js;

      js_set $jwt jwt;

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
        var header = { typ: "JWT",
                       alg: "HS256",
                       exp: Math.floor(Date.now()/1000) + valid };

        var s = [header, claims].map(JSON.stringify)
                                .map(v=>v.toBytes())
                                .map(v=>v.toString('base64url'))
                                .join('.');

        var h = require('crypto').createHmac('sha256', key);

        return s + '.' + h.update(s).digest().toString('base64url');
    }

    function jwt(r) {
        var claims = {
            iss: "nginx",
            sub: "alice",
            foo: 123,
            bar: "qq",
            zyx: false
        };

        return generate_hs256_jwt(claims, 'foo', 600);
    }

Checking:

.. code-block:: shell

  curl 'http://localhost/jwt'
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImV4cCI6MTU4NDcyMjk2MH0.eyJpc3MiOiJuZ2lueCIsInN1YiI6ImFsaWNlIiwiZm9vIjoxMjMsImJhciI6InFxIiwienl4IjpmYWxzZX0.GxfKkJSWI4oq5sGBg4aKRAcFeKmiA6v4TR43HbcP2X8

Injecting HTTP header using stream proxy [stream/inject_header]
========================================

nginx.conf:

.. code-block:: nginx

  ...

  stream {
      js_include example.js;

      server {
            listen 80;

            proxy_pass 127.0.0.1:8080;
            js_filter inject_header;
      }
  }

  ...

example.js:

.. code-block:: js

    function inject_header(s) {
        inject_my_header(s, 'Foo: my_foo');
    }

    function inject_my_header(s, header) {
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

Checking:

.. code-block:: shell

  curl http://localhost/
  my_foo


Subrequests join [join_subrequests]
================
Combining the results of several subrequests asynchronously into a single JSON reply.

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.js;

      server {
            listen 80;

            location /join {
                js_content join;
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

Checking:

.. code-block:: shell

  curl http://localhost/join
  [{"uri":"/foo","code":200,"body":"FOO"},{"uri":"/bar","code":200,"body":"BAR"}]



Secure hash [secure_link_hash]
================
Protecting ``/secure/`` location from simple bots and web crawlers.

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.js;

      js_set $new_foo create_secure_link;

      server {
            listen 80;

            location /secure/ {
                error_page 403 = @login;

                secure_link $cookie_foo;
                secure_link_md5 "$uri mykey";

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

  function create_secure_link(r) {
    return require('crypto').createHash('md5')
                            .update(r.uri).update(" mykey")
                            .digest('base64url');
  }

Checking:

.. code-block:: shell

  curl http://127.0.0.1/secure/r
  302

  curl http://127.0.0.1/secure/r -L
  curl: (47) Maximum (50) redirects followed

  curl http://127.0.0.1/secure/r --cookie-jar cookie.txt
  302

  curl http://127.0.0.1/secure/r --cookie cookie.txt
  PASSED


File IO [file_io]
================

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

Complex redirects using njs file map [complex_redirects]
========================================

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.js;

      upstream backend {
        server 127.0.0.1:8080;
      }

      server {
            listen 80;

            location = /version {
                js_content version;
            }

            # PROXY

            location / {
                auth_request /resolv;
                auth_request_set $route $sent_http_route;

                proxy_pass http://backend$route$is_args$args;
            }

            location = /resolv {
                internal;

                js_content resolv;
            }
      }

      ...
  }

example.js:

.. code-block:: js

    ...

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
    ...

Checking:

.. code-block:: shell

  curl http://localhost/CCC?a=1
  200 /CCC?a=1

  curl http://localhost:8090/map
  200 {}

  curl http://localhost:8090/add -X POST --data '{"from": "/CCC", "to": "/AA"}'
  200

  curl http://localhost:8090/add -X POST --data '{"from": "/BBB", "to": "/DD"}'
  200

  curl http://localhost/CCC?a=1
  200 /AA?a=1

  curl http://localhost/BB?a=1
  200 /BB?a=1

  curl http://localhost:8090/map
  200 {"/CCC":"/AA","/BBB":"/DD"}

  curl http://localhost:8090/remove -X POST --data '{"from": "/CCC"}'
  200

  curl http://localhost:8090/map
  200 {"/BBB":"/DD"}

  curl http://localhost/CCC?a=1
  200 /CCC?a=1


Command line
============

.. code-block:: shell

  docker run -i -t nginx:latest /usr/bin/njs

.. code-block:: none

    interactive njs 0.3.9

    v.<Tab> -> the properties and prototype methods of v.

    >> globalThis
    global {
     njs: njs {
      version: '0.3.9'
     },
     global: [Circular],
     process: process {
      argv: [
       '/usr/bin/njs'
      ],
      env: {
       PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       HOSTNAME: 'f777c149d4f8',
       TERM: 'xterm',
       NGINX_VERSION: '1.17.9',
       NJS_VERSION: '0.3.9',
       PKG_RELEASE: '1~buster',
       HOME: '/root'
      }
     },
     console: {
      log: [Function: native],
      dump: [Function: native],
      time: [Function: native],
      timeEnd: [Function: native]
     },
     print: [Function: native]
    }
