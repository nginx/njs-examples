=================
NGINX JavaScript examples
=================

****************
Table of content
****************

- Intro_
- `Authorization <https://github.com/xeioex/njs-examples/blob/master/authorization.rst>`
- CLI_

.. _Intro:

Intro
=====

Note: the examples below work with njs >= `0.4.0 <http://nginx.org/en/docs/njs/changes.html#njs0.4.0>`_, see `this version <https://github.com/xeioex/njs-examples/tree/b1c992c742b5d41dea2e087ebea98e098543a341>`_ for older releases.

Running inside Docker:

.. code-block:: shell

  git clone https://github.com/xeioex/njs-examples
  cd njs-examples
  EXAMPLE='hello'
  docker run --rm --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro  -v $(pwd)/njs/$EXAMPLE.js:/etc/nginx/example.js:ro -v $(pwd)/njs/utils.js:/etc/nginx/utils.js:ro -p 80:80 -p 8090:8090 -d nginx

  # Stopping.
  docker stop njs_example

Hello world [hello]
===========

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

Subrequests join [join_subrequests]
================
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


Subrequests chaining [subrequests_chaining]
================
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


File IO [file_io]
================

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

Choosing upstream in stream based on the underlying protocol [stream/detect_http]
========================================

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

.. _CLI:

Command line
============

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
