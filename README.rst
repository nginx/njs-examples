=================
NGINX JavaScript examples
=================


Examples
********

Running inside Docker:

.. code-block:: shell

  git clone https://github.com/xeioex/njs-examples
  cd njs-examples
  EXAMPLE=hello
  docker run --rm --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro  -v $(pwd)/njs/$EXAMPLE.njs:/etc/nginx/example.njs:ro -p 80:80 -p 8090:8090 -d nginx

  # Stopping.
  docker stop njs_example

Hello world
===========

nginx.conf:

.. code-block:: nginx

  load_module modules/ngx_http_js_module.so;

  events {}

  http {
    js_include example.njs;

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

example.njs:

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

Decode URI
===========

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.njs;

      js_set $dec_foo dec_foo;

      server {
  ...
            location /foo {
                return 200 $arg_foo;
            }

            location /dec_foo {
                return 200 $dec_foo;
            }
      }
  }

example.njs:

.. code-block:: js

  function dec_foo(r) {
    return decodeURIComponent(r.args.foo);
  }

Checking:

.. code-block:: shell

  curl -G http://localhost/foo --data-urlencode "foo=привет"
  %D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82

  curl -G http://localhost/dec_foo --data-urlencode "foo=привет"
  привет

Injecting HTTP header using stream proxy
========================================

nginx.conf:

.. code-block:: nginx

  ...

  stream {
      js_include example.njs;

      server {
            listen 80;

            proxy_pass 127.0.0.1:8080;
            js_filter inject_header;
      }
  }

  ...

example.njs:

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


Subrequests join
================
Combining the results of several subrequests asynchronously into a single JSON reply.

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.njs;

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

example.njs:

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



Secure hash
================
Protecting ``/secure/`` location from simple bots and web crawlers.

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.njs;

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

example.njs:

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


File IO
================

example.njs:

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

Complex redirects using njs file map.
========================================

nginx.conf:

.. code-block:: nginx

  ...

  http {
      js_include example.njs;

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
                auth_request_set $route $upstream_http_route;

                proxy_pass http://backend$route$is_args$args;
            }

            location = /resolv {
                internal;

                proxy_pass http://127.0.0.1:8090/resolv;
                proxy_pass_request_body off;
                proxy_set_header Content-Length "";
                proxy_set_header X-Original-URI $request_uri;
            }
      }

      ...
  }

example.njs:

.. code-block:: js

    ...

    function resolv(r) {
        try {
            var map = open_db();
            var uri = r.headersIn['X-Original-URI'].split("?")[0];

            if (!uri) {
                r.return(400, "Can't find \"X-Original-URI\" header, required");
                return;
            }

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

  interactive njs 0.2.4

  v.<Tab> -> the properties and prototype methods of v.
  type console.help() for more information

  >> function hi(msg) {console.log(msg)}
  undefined
  >> hi("Hello world")
  'Hello world'
  undefined
