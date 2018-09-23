=================
NGINX JavaScript examples
=================


Examples
********

Hello world
===========

hello.conf:

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

hello.njs:

.. code-block:: js

  function version(r) {
    r.return(200, njs.version);
  }

  function hello(r) {
    r.return(200, "Hello world!\n");
  }
 
Running inside Docker:

.. code-block:: shell

  git clone https://github.com/xeioex/njs-examples
  cd njs-examples
  docker run --name hello  -v $(pwd)/conf/hello.conf:/etc/nginx/nginx.conf:ro  -v $(pwd)/njs/hello.njs:/etc/nginx/hello.njs    -p 80:80 -d nginx

Checking:

.. code-block:: shell

  curl http://localhost/hello
  Hello world!

  curl http://localhost/version
  0.2.3


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
