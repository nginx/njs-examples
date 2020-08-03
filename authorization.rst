=================
NGINX Authorization JavaScript examples
=================

Getting arbitrary field from JWT as a nginx variable [jwt]
===========

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
            .map(v=>String.bytesFrom(v, 'base64url'))
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

Generating JWT token [gen_hs_jwt]
===========

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
                                .map(v=>v.toUTF8())
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

        return generate_hs256_jwt(claims, process.env.JWT_GEN_KEY, 600);
    }

    export default {jwt}

Checking:

.. code-block:: shell

  docker run --rm --name njs_example -e JWT_GEN_KEY="foo" ...

  curl 'http://localhost/jwt'
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImV4cCI6MTU4NDcyMjk2MH0.eyJpc3MiOiJuZ2lueCIsInN1YiI6ImFsaWNlIiwiZm9vIjoxMjMsImJhciI6InFxIiwienl4IjpmYWxzZX0.GxfKkJSWI4oq5sGBg4aKRAcFeKmiA6v4TR43HbcP2X8


Secure hash [secure_link_hash]
================
Protecting ``/secure/`` location from simple bots and web crawlers.

nginx.conf:

.. code-block:: nginx

  env JWT_GEN_KEY;

  ...

  http {
    js_import utils.js;
    js_import main from example.js;

    js_set $new_foo main.create_secure_link;

    server {
          listen 80;

          ...

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
                            .update(r.uri).update(process.env.JWT_GEN_KEY)
                            .digest('base64url');
  }

  export default {create_secure_link}

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

