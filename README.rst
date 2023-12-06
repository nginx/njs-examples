=========================
NGINX JavaScript examples
=========================

.. contents::
   :depth: 3

Intro
=====

This repo contains complete examples for various use cases where `njs <http://nginx.org/en/docs/njs/>`_ is useful. The document as well as `njs documentation <http://nginx.org/en/docs/njs/>`_ expects some familiarity with and understanding of nginx. Beginners should refer to the official `admin guide <https://docs.nginx.com/nginx/admin-guide/>`_.

Note: the examples below work with njs >= `0.7.0 <http://nginx.org/en/docs/njs/changes.html#njs0.7.0>`_. To see the current version run the following command: ``docker run -i -t nginx:latest /usr/bin/njs -V``.

Running inside Docker
---------------------
Public nginx docker image contains open source version of nginx. To run examples for NGINX-PLUS, you have to `build <https://www.nginx.com/blog/deploying-nginx-nginx-plus-docker/>`_ your own docker image.

.. code-block:: shell

  git clone https://github.com/nginx/njs-examples
  cd njs-examples
  EXAMPLE='http/hello'
  docker run --rm --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro -v $(pwd)/njs/:/etc/nginx/njs/:ro -p 80:80 -p 443:443 -d nginx
  # for NGINX-PLUS examples,
  # docker run ... -d mynginxplus

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

Extending NGINX with Custom Code
--------------------------------
https://youtu.be/0CVhq4AUU7M

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

Setting nginx var as a result of async operation
------------------------------------------------
`js_set <https://nginx.org/en/docs/http/ngx_http_js_module.html#js_set>`_ handler
does not support asynchronous operation (r.subrequest(), ngx.fetch()) because it is
invoked in a synchronous context by nginx and is expected to return its result
right away. Fortunately there are ways to overcome this limitation using other
nginx modules.

The examples in this section is provided in order from simple to more advanced.
The simplest method are preferred because generally they are more efficient.

Using auth_request [http/async_var/auth_request]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In simple cases `auth_request <http://nginx.org/en/docs/http/ngx_http_auth_request_module.html>`_
is enough and njs is not required.

Simple case criteria:
   - request body is not needed to be forwarded
   - external service returns the desired value extractable as an nginx variable (for example as a response header)

The following example illustrates this use case using njs ONLY as a fake service.
$backend variable is populated by auth_request module from a response header of a subrequest.

nginx.conf:

.. code-block:: nginx

    ...

    http {
      js_path "/etc/nginx/njs/";

      js_import main from http/async_var/auth_request.js;

      server {
          listen 80;

          location /secure/ {
              auth_request /fetch_upstream;
              auth_request_set $backend $upstream_http_x_backend;

              proxy_pass http://$backend;
          }

          location /fetch_upstream {
              internal;

              proxy_pass http://127.0.0.1:8079;
              proxy_pass_request_body off;
              proxy_set_header Content-Length "";
              proxy_set_header X-Original-URI $request_uri;
          }
      }

      server {
          listen 127.0.0.1:8079;

          location / {
            js_content main.choose_upstream;
          }
      }

      server {
          listen 127.0.0.1:8081;
          return 200 "BACKEND A:$uri\n";
      }

      server {
          listen 127.0.0.1:8082;
          return 200 "BACKEND B:$uri\n";
      }
    }

example.js:

.. code-block:: js

    import qs from "querystring";

    function choose_upstream(r) {
        let backend;
        let args = qs.parse(r.headersIn['X-Original-URI'].split('?')[1]);

        switch (args.token) {
        case 'A':
            backend = '127.0.0.1:8081';
            break;
        case 'B':
            backend = '127.0.0.1:8082';
            break;
        default:
            r.return(404);
        }

        r.headersOut['X-backend'] = backend;
        r.return(200);
    }

    export default {choose_upstream}

Checking:

.. code-block:: shell

    curl http://localhost/secure/abc?token=A
    BACKEND A:/secure/abc

    curl http://localhost/secure/abcde?token=B
    BACKEND B:/secure/abcde

Using auth_request and js_header_filter [http/async_var/js_header_filter]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
`js_header_filter <http://nginx.org/en/docs/http/ngx_http_js_module.html#js_header_filter>`_
can be used to modify the service response and set an appropriate response header of
an auth_request subrequest. This case is applicable when a service returns a value which
cannot be used directly.

nginx.conf:

.. code-block:: nginx

    ...

    http {
      js_path "/etc/nginx/njs/";

      js_import main from http/async_var/js_header_filter.js;

      server {
          listen 80;

          location /secure/ {
              auth_request /fetch_upstream;
              auth_request_set $backend $sent_http_x_backend;

              proxy_pass http://$backend;
          }

          location /fetch_upstream {
              internal;

              proxy_pass http://127.0.0.1:8079;
              proxy_pass_request_body off;
              proxy_set_header Content-Length "";
              proxy_set_header X-Original-URI $request_uri;

              js_header_filter main.set_upstream;
          }
      }

      server {
          listen 127.0.0.1:8079;

          location / {
            js_content main.choose_upstream;
          }
      }

      server {
          listen 127.0.0.1:8081;
          return 200 "BACKEND A:$uri\n";
      }

      server {
          listen 127.0.0.1:8082;
          return 200 "BACKEND B:$uri\n";
      }
    }

example.js:

.. code-block:: js

    import qs from "querystring";

    function choose_upstream(r) {
        let backend;
        let args = qs.parse(r.headersIn['X-Original-URI'].split('?')[1]);

        switch (args.token) {
        case 'A':
            backend = 'B1';
            break;
        case 'B':
            backend = 'B2';
            break;
        default:
            r.return(404);
        }

        r.headersOut['X-backend'] = backend;
        r.return(200);
    }

    function set_upstream(r) {
        let backend;
        switch (r.headersOut['X-backend']) {
        case 'B1':
            backend = '127.0.0.1:8081';
            break;
        case 'B2':
            backend = '127.0.0.1:8082';
            break;
        }

        if (backend) {
            r.headersOut['X-backend'] = backend;
        }
    }

    export default {choose_upstream, set_upstream}

Checking:

.. code-block:: shell

    curl http://localhost/secure/abc?token=A
    BACKEND A:/secure/abc

    curl http://localhost/secure/abcde?token=B
    BACKEND B:/secure/abcde

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

    async function generate_hs256_jwt(init_claims, key, valid) {
        let header = { typ: "JWT",  alg: "HS256" };
        let claims = Object.assign(init_claims, {exp: Math.floor(Date.now()/1000) + valid});

        let s = [header, claims].map(JSON.stringify)
                                .map(v=>Buffer.from(v).toString('base64url'))
                                .join('.');

        let wc_key = await crypto.subtle.importKey('raw', key, {name: 'HMAC', hash: 'SHA-256'},
                                                   false, ['sign']);
        let sign = await crypto.subtle.sign({name: 'HMAC'}, wc_key, s);

        return s + '.' + Buffer.from(sign).toString('base64url');
    }

    async function jwt(r) {
        let claims = {
            iss: "nginx",
            sub: "alice",
            foo: 123,
            bar: "qq",
            zyx: false
        };

        let jwtv = await generate_hs256_jwt(claims, process.env.JWT_GEN_KEY, 600);
        r.setReturnValue(jwtv);
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
            var body  = r.requestText;
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

Securely serve encrypted traffic without server restarts when certificate or key changes occur. [http/certs/dynamic]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Configure NGINX to serve encrypted traffic without server restarts when certificate or key changes occur by using `js_shared_dict_zone <https://nginx.org/en/docs/http/ngx_http_js_module.html#js_shared_dict_zone>`_ as a cache.

Note: this example below work with njs >= `0.8.0 <http://nginx.org/en/docs/njs/changes.html#njs0.8.0>`_.

This example demonstrates:

 - Use of `js_set <https://nginx.org/en/docs/http/ngx_http_js_module.html#js_set>`_ in combination with ``ssl_certificate data:$var;`` to use NJS to resolve value of cert/key during handshake.
 - Use of `js_shared_dict_zone <https://nginx.org/en/docs/http/ngx_http_js_module.html#js_shared_dict_zone>`_ to store cert/key in memory.
 - Implementation a simple RESTful API to manage ``shared_dict`` to get/set certificate/key files.
 - How to deal with ``Content-Disposition`` while handling file uploads in NJS.

nginx.conf:

.. code-block:: nginx

  ...

  load_module modules/ngx_http_js_module.so;
  error_log /dev/stdout debug;
  events {  }

  http {
    js_path "/etc/nginx/njs/";
    js_import main from http/certs/js/dynamic.js;
    js_shared_dict_zone zone=kv:1m;

    server {
      listen 80;
      listen 443 ssl;
      server_name www.example.com;

      js_var $shared_dict_zone_name kv;
      js_var $cert_folder '/tmp/';

      js_set $dynamic_ssl_cert main.js_cert;
      js_set $dynamic_ssl_key main.js_key;

      ssl_password_file /etc/nginx/njs/http/certs/ca/password;
      ssl_certificate data:$dynamic_ssl_cert;
      ssl_certificate_key data:$dynamic_ssl_key;

      location = / {
        js_content main.info;
      }

      location /kv {
        js_content main.kv;
      }

      location = /clear {
        js_content main.clear_cache;
      }
    }

  }


Here we would implement ``js_set`` handlers that reads cert/key from a FS or from `shared_dict`` (used as a cache here):

.. code-block:: js

  function js_cert(r) {
    if (r.variables['ssl_server_name']) {
      return read_cert_or_key(r, '.cert.pem');
    } else {
      return '';
    }
  }

  function js_key(r) {
    if (r.variables['ssl_server_name']) {
      return read_cert_or_key(r, '.key.pem');
    } else {
      return '';
    }
  }

  function joinPaths(...args) {
    return args.join('/').replace(/\/+/g, '/');
  }

  function read_cert_or_key(r, fileExtension) {
    let data = '';
    let path = '';
    const zone = r.variables['shared_dict_zone_name'];
    let certName = r.variables.ssl_server_name;
    let prefix = r.variables['cert_folder'] || '/etc/nginx/certs/';
    path = joinPaths(prefix, certName + fileExtension);
    r.log(`Resolving ${path}`);
    const key = ['certs', path].join(':');
    const cache = zone && ngx.shared && ngx.shared[zone];

    if (cache) {
      data = cache.get(key) || '';
      if (data) {
        r.log(`Read ${key} from cache`);
        return data;
      }
    }
    try {
      data = fs.readFileSync(path, 'utf8');
      r.log('Read from cache');
    } catch (e) {
      data = '';
      r.log(`Error reading from file:', ${path}, . Error=${e}`);
    }
    if (cache && data) {
      try {
        cache.set(key, data);
        r.log('Persisted in cache');
      } catch (e) {
        const errMsg = `Error writing to shared dict zone: ${zone}. Error=${e}`;
        r.log(errMsg);
      }
    }
    return data
  }

The rest of code can be found in the `njs/http/certs/js/dynamic.js <njs/http/certs/js/dynamic.js>`_.

Checking:

.. code-block:: shell

  # when started and there is no cert/key it fails to serve HTTPS
  curl -k --resolve www.example.com:443:127.0.0.1 https://www.example.com:443

  curl http://localhost/

  # Upload cert/key files. file name would be used to form a key for shared_dict
  curl -iv http://localhost:80/kv -F cert=@njs/http/certs/ca/intermediate/certs/www.example.com.cert.pem -F key=@njs/http/certs/ca/intermediate/private/www.example.com.key.pem

  # Get Certificate from shared_dict:
  curl http://localhost/kv/www.example.com.cert.pem

  # Get Private Key from shared_dict:
  curl http://localhost/kv/www.example.com.key.pem

  # now we can test HTTPS again
  curl -k --resolve www.example.com:443:127.0.0.1 https://www.example.com

  # Clear shared_dict
  curl http://localhost/clear


Fetch
-----

HTTPS fetch example [http/certs/fetch_https]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx.conf:

.. code-block:: nginx

    ...

    http {
          js_path "/etc/nginx/njs/";

          js_import main from http/certs/js/fetch_https.js;

          resolver 1.1.1.1;

          server {
                listen 80;

                location / {
                    js_content main.fetch;
                    js_fetch_trusted_certificate /etc/nginx/njs/http/certs/ISRG_Root_X1.pem;
                }
          }
    }

example.js:

.. code-block:: js

    async function fetch(r) {
        let reply = await ngx.fetch('https://nginx.org/');
        let text = await reply.text();
        let footer = "----------NGINX.ORG-----------";

        r.return(200, `${footer}\n${text.substring(0, 200)} ...${text.length - 200} left...\n${footer}`);
    }

    export default {fetch};

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

    async function join(r) {
        join_subrequests(r, ['/foo', '/bar']);
    }

    async function join_subrequests(r, subs) {
        let results = await Promise.all(subs.map(uri => r.subrequest(uri)));

         let response = results.map(reply => ({
            uri:  reply.uri,
            code: reply.status,
            body: reply.responseText,
         }));

        r.return(200, JSON.stringify(response));
    }

    export default {join};

Checking:

.. code-block:: shell

  curl http://localhost/join
  [{"uri":"/foo","code":200,"body":"FOO"},{"uri":"/bar","code":200,"body":"BAR"}]


Subrequests chaining [http/subrequests_chaining]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Subrequests chaining.

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

    async function process(r) {
        try {
            let reply = await r.subrequest('/auth')
            let response = JSON.parse((reply.responseText));
            let token = response['token'];

            if (!token) {
                throw new Error("token is not available");
            }

            let backend_reply = await r.subrequest('/backend', `token=${token}`);
            r.return(backend_reply.status, backend_reply.responseText);

        } catch (e) {
            r.return(500, e);
        }
    }

    function authenticate(r) {
        let auth = r.headersIn.Authorization;
        if (auth && auth.slice(7) === 'secret') {
            r.return(200, JSON.stringify({status: "OK", token:42}));
            return;
        }

        r.return(403, JSON.stringify({status: "INVALID"}));
    }

    export default {process, authenticate};

Checking:

.. code-block:: shell

  curl http://localhost/start -H 'Authorization: Bearer secret'
  Token is 42

  curl http://localhost/start
  Error: token is not available

  curl http://localhost/start -H 'Authorization: Bearer secre'
  Error: token is not available

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

Logging
-------

Logging the Number of Requests Per Client [http/logging/num_requests]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note:: The `keyval <http://nginx.org/en/docs/http/ngx_http_keyval_module.html#keyval>`_ and `keyval_zone <http://nginx.org/en/docs/http/ngx_http_keyval_module.html#keyval_zone>`_ directives are available as part of our `commercial subscription <https://www.nginx.com/products/nginx/>`_.

In this example `keyval <http://nginx.org/en/docs/http/ngx_http_keyval_module.html#keyval>`_ is used to count (accross all nginx workers) the incoming requests from the same ip address.

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import main from http/logging/num_requests.js;

    js_set $num_requests http.num_requests;

    keyval_zone zone=foo:10m;

    keyval $remote_addr $foo zone=foo;

    log_format bar '$remote_addr [$time_local] $num_requests';

    access_log logs/access.log bar;

    server {
          listen 80;

          location / {
              return 200;
          }
    }
  }

example.js:

.. code-block:: js

    function num_requests(r) {
        var n = r.variables.foo;
        n = n ? Number(n) + 1 : 1;
        r.variables.foo = n;
        return n;
    }

    export default {num_requests};

Checking:

.. code-block:: shell

  curl http://localhost/aa; curl http://localhost/aa; curl http://localhost/aa
  curl --interface 127.0.0.2 http://localhost/aa; curl --interface 127.0.0.2 http://localhost/aa

  docker logs njs_example
  127.0.0.1 [22/Nov/2021:16:55:06 +0000] 1
  127.0.0.1 [22/Nov/2021:16:55:07 +0000] 2
  127.0.0.1 [22/Nov/2021:16:55:29 +0000] 3
  127.0.0.2 [22/Nov/2021:18:20:24 +0000] 1
  127.0.0.2 [22/Nov/2021:18:20:25 +0000] 2

Shared Dictionary
-----------------

HTTP Rate limit[http/rate-limit/simple]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this example `js_shared_dict_zone <https://nginx.org/en/docs/http/ngx_http_js_module.html#js_shared_dict_zone>`_ is used to implement a simple rate limit and can be set in different contexts.
The rate limit is implemented using a shared dictionary zone and a simple javascript function that is called for each request and increments the counter for the current window.
If the counter exceeds the limit, the function returns the number of seconds until the end of the window. The function is called using
`js_set <https://nginx.org/en/docs/http/ngx_http_js_module.html#js_set>`_ and the result is stored in a variable that is used to return a 429 response if the limit is exceeded.

nginx.conf:

.. code-block:: nginx

    http {
      js_path "/etc/nginx/njs/";
      js_import main from http/rate-limit/simple.js;
      # optionally set timeout so NJS resets and deletes all data for ratelimit counters
      js_shared_dict_zone zone=kv:1M timeout=3600s evict;

      server {
        listen 80;
        server_name www.example.com;
        # access_log off;
        js_var $rl_zone_name kv;          # shared dict zone name; requred variable
        js_var $rl_windows_ms 30000;      # optional window in miliseconds; default 1 minute window if not set
        js_var $rl_limit 10;              # optional limit for the window; default 10 requests if not set
        js_var $rl_key $remote_addr;      # rate limit key; default remote_addr if not set
        js_set $rl_result main.ratelimit; # call ratelimit function that returns retry-after value if limit is exceeded

        location = / {
          # test rate limit result
          if ($rl_result != "0") {
            add_header Retry-After $rl_result always;
            return 429 "Too Many Requests.";
          }
          # Your normal processing here
          return 200 "hello world";
        }
      }
    }

example.js:

.. code-block:: js

    const defaultResponse = "0";
    function ratelimit(r) {
        const zone = r.variables['rl_zone_name'];
        const kv = zone && ngx.shared && ngx.shared[zone];
        if (!kv) {
            r.log(`ratelimit: ${zone} js_shared_dict_zone not found`);
            return defaultResponse;
        }

        const key = r.variables['rl_key'] || r.variables['remote_addr'];
        const window = Number(r.variables['rl_windows_ms']) || 60000;
        const limit = Number(r.variables['rl_limit']) || 10;
        const now = Date.now();

        let requestData = kv.get(key);
        if (requestData === undefined || requestData.length === 0) {
            requestData = { timestamp: now, count: 1 }
            kv.set(key, JSON.stringify(requestData));
            return defaultResponse;
        }
        try {
            requestData = JSON.parse(requestData);
        } catch (e) {
            requestData = { timestamp: now, count: 1 }
            kv.set(key, JSON.stringify(requestData));
            return defaultResponse;
        }
        if (!requestData) {
            requestData = { timestamp: now, count: 1 }
            kv.set(key, JSON.stringify(requestData));
            return defaultResponse;
        }
        if (now - requestData.timestamp >= window) {
            requestData.timestamp = now;
            requestData.count = 1;
        } else {
            requestData.count++;
        }
        const elapsed = now - requestData.timestamp;
        r.log(`limit: ${limit} window: ${window} elapsed: ${elapsed}  count: ${requestData.count} timestamp: ${requestData.timestamp}`)
        let retryAfter = 0;
        if (requestData.count > limit) {
            retryAfter = Math.ceil((window - elapsed) / 1000);
        }
        kv.set(key, JSON.stringify(requestData));
        return retryAfter.toString();
    }

    export default { ratelimit };


.. code-block:: shell

  curl http://localhost
  200 hello world

  curl http://localhost
  200 hello world

  # 3rd request should fail according to the rate limit $rl_limit=2
  curl http://localhost
  429 rate limit exceeded


NGINX-PLUS API
--------------

Setting keyval using a subrequest [http/api/set_keyval]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note:: The `keyval <http://nginx.org/en/docs/http/ngx_http_keyval_module.html#keyval>`_, `api <http://nginx.org/en/docs/http/ngx_http_api_module.html#api>`_ and `keyval_zone <http://nginx.org/en/docs/http/ngx_http_keyval_module.html#keyval_zone>`_ directives are available as part of our `commercial subscription <https://www.nginx.com/products/nginx/>`_.

nginx.conf:

.. code-block:: nginx

  ...

  http {
    js_path "/etc/nginx/njs/";

    js_import main from http/api/set_keyval.js;

    keyval_zone zone=foo:10m;

    server {
          listen 80;

          location /keyval {
              js_content main.set_keyval;
          }

          location /api {
              internal;
              api write=on;
          }

          location /api/ro {
              api;
          }
    }

example.js:

.. code-block:: js

    async function set_keyval(r) {
        let method = r.args.method ? r.args.method : 'POST';
        let res = await r.subrequest('/api/7/http/keyvals/foo',
                                     { method, body: r.requestText});

        if (res.status >= 300) {
            r.return(res.status, res.responseText);
            return;
        }

        r.return(200);
    }

    export default {set_keyval};

Checking:

.. code-block:: shell

  curl http://localhost/api/ro/7/http/keyvals/foo
  {}
  curl http://localhost:8000/keyval -d '{"a":1}'
  OK
  curl http://localhost/api/ro/7/http/keyvals/foo
  {"a":"1"}
  curl http://localhost:8000/keyval -d '{"a":2}'
  {"error":{"status":409,"text":"key \"a\" already exists","code":"KeyvalKeyExists"},"request_id":"cbec775883f6b10f2fe79e27d3f249ce","href":"https://nginx.org/en/docs/http/ngx_http_api_module.html"}
  curl http://localhost:8000/keyval?method=PATCH -d '{"a":2}'
  OK
  curl http://localhost:8000/api/ro/7/http/keyvals/foo
  {"a":"2"}

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

      s.on('upload', async function (data, flags) {
          collect += data;

          if (collect.length >= 5 && collect.startsWith('MAGiK')) {
              s.off('upload');
              let reply = ngx.fetch('http://127.0.0.1:8080/validate',
                                    {body: collect.slice(5,7),
                                     headers: {Host:'aaa'}});

              (reply.status == 200) ? s.done(): s.deny();

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
          fs.appendFileSync(STORAGE, r.requestText);
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

Webcrypto (AES-GSM) [misc/aes_gsm]
----------------------------------

nginx.conf:

.. code-block:: nginx

    http {
      js_path "/etc/nginx/njs/";

      js_import main from misc/aes_gsm.js;

      server {
            listen 80;

            location /encrypt {
                js_content main.encrypt;
            }

            location /decrypt {
                js_content main.decrypt;
            }
      }
    }

example.js:

.. code-block:: js

    async function encryptUAM(key_in, iv, text) {
        const alg = { name: 'AES-GCM', iv: iv ? Buffer.from(iv, 'hex')
                                              : crypto.getRandomValues(new Uint8Array(12)) };

        const sha256 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key_in));
        const key = await crypto.subtle.importKey('raw', sha256, alg, false, ['encrypt']);

        const cipher = await crypto.subtle.encrypt(alg, key, new TextEncoder().encode(text));

        return JSON.stringify({
            cipher: btoa(String.fromCharCode.apply(null, new Uint8Array(cipher))),
                iv: btoa(String.fromCharCode.apply(null, new Uint8Array(alg.iv))),
        });
    }

    async function decryptUAM(key_in, value) {
        value = JSON.parse(value);

        ngx.log(ngx.ERR, njs.dump(value))
        const alg = { name: 'AES-GCM', iv: Buffer.from(value.iv, 'base64') };
        const sha256 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key_in));
        const key = await crypto.subtle.importKey('raw', sha256, alg, false, ['decrypt']);

        const decrypt = await crypto.subtle.decrypt(alg, key, Buffer.from(value.cipher, 'base64'));
        ngx.log(ngx.ERR, njs.dump(new Uint8Array(decrypt)))
        return new TextDecoder().decode(decrypt);
    }

    async function encrypt(r) {
        try {
            let encrypted = await encryptUAM(r.args.key, r.args.iv, r.requestText);
            r.return(200, encrypted);
        } catch (e) {
            r.return(500, `encryption failed with ${e.message}`);
        }
    }

    async function decrypt(r) {
        try {
            let decrypted = await decryptUAM(r.args.key, r.requestText);
            r.return(200, decrypted);
        } catch (e) {
            r.return(500, `decryption failed with ${e.message}`);
        }
    }

    export default {encrypt, decrypt};

.. code-block:: shell

    curl 'http://localhost/encrypt?key=mySecret&iv=000000000000000000000001' -d TEXT-TO-BE-ENCODED
    {"cipher":"kLKXeb/h1inwXYlP7M504xCD+/1sF4yesCSUc7/OJiyPyw==","iv":"AAAAAAAAAAAAAAAB"}

    curl 'http://localhost/decrypt?key=mySecret' -d '{"cipher":"kLKXeb/h1inwXYlP7M504xCD+/1sF4yesCSUc7/OJiyPyw==","iv":"AAAAAAAAAAAAAAAA"}'
    decryption failed with EVP_DecryptFinal_ex() failed

    curl 'http://localhost/decrypt?key=mySecre' -d '{"cipher":"kLKXeb/h1inwXYlP7M504xCD+/1sF4yesCSUc7/OJiyPyw==","iv":"AAAAAAAAAAAAAAAB"}'
    decryption failed with EVP_DecryptFinal_ex() failed

    curl 'http://localhost/decrypt?key=mySecret' -d '{"cipher":"kLKXeb/h1inwXYlP7M504xCD+/1sF4yesCSUc7/OJiyPyw==","iv":"AAAAAAAAAAAAAAAB"}'
    TEXT-TO-BE-ENCODED

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

* `soulteary/njs-learning-materials <https://github.com/soulteary/njs-learning-materials>`_
* `4141done/talks-njs_for_fun <https://github.com/4141done/talks-njs_for_fun>`_
