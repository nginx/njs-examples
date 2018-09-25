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
  docker run --name njs_example  -v $(pwd)/conf/$EXAMPLE.conf:/etc/nginx/nginx.conf:ro  -v $(pwd)/njs/$EXAMPLE.njs:/etc/nginx/example.njs:ro -p 80:80 -d nginx
  
  # Stopping.
  docker stop njs_example && docker rm njs_example

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
  0.2.3

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

Subrequests join
================
Combining the results of several subrequests asynchronously into a single JSON reply.

nginx.conf:

.. code-block:: nginx

  load_module modules/ngx_http_js_module.so;
    
  events {}
  
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

Command line
============

.. code-block:: shell

  docker run -i -t nginx:latest /usr/bin/njs

.. code-block:: none

  interactive njs 0.2.3

  v.<Tab> -> the properties and prototype methods of v.
  type console.help() for more information

  >> function hi(msg) {console.log(msg)}
  undefined
  >> hi("Hello world")
  'Hello world'
  undefined
