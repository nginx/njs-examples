=================
NGINX JavaScript examples
=================


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
  0.2.4
