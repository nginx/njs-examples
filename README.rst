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
    js_include hello.njs; 
    
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
