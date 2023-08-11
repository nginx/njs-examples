/**
 * NGINX Secure Traffic Serving - JavaScript Module
 *
 * This JavaScript module enables NGINX to securely serve encrypted traffic without server restarts when certificate or key changes occur.
 *
 * Usage:
 * 1. Install and configure NGINX with the NJS module.
 * 2. Include the provided JavaScript module (dynamic.js) in your NGINX configuration.
 * 3. Set up an HTTP endpoint to handle file uploads (e.g., /upload).
 * 4. Clients can use the endpoint to upload certificate and key files using the 'curl' command, like so:
 *    curl http://localhost:8000/upload -F cert=@/path/www.example.com.crt -F key=@/path/www.example.com.key
 *
 * Benefits:
 * - Dynamic SSL certificate and key management without server restarts.
 * - Handle certs/keys file uploads.
 * - Efficient and uninterrupted serving of encrypted traffic using shared_dict to minimize disk IO and cache certs/keys.
 *
 * Note:
 * - Ensure appropriate file permissions for the NGINX server to write uploaded files.
 * - Validate and sanitize uploaded file content to prevent security risks.
 */

import fs from 'fs'

/**
 * Retrieves the cert value
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string, string} - The cert associated with the server name.
 */
function js_cert(r) {
  if (r.variables['ssl_server_name']) {
    return read_cert_or_key(r, '.cert.pem');
  } else {
    return '';
  }
}

/**
 * Retrieves the key value
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @returns {string} - The key associated with the server name.
 */
function js_key(r) {
  if (r.variables['ssl_server_name']) {
    return read_cert_or_key(r, '.key.pem');
  } else {
    return '';
  }
}

/**
 * Join args with a slash remove duplicate slashes
 */
function joinPaths(...args) {
  return args.join('/').replace(/\/+/g, '/');
}

/**
 * Retrieves the key/cert value from file cache or disk
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 * @param {string} fileExtension - The file extension
 * @returns {string} - The key/cert associated with the ssl_server_name.
 */
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

function keyFromURI(uri) {
  if (!uri || typeof uri !== 'string') {
    return null;
  }
  const trimmedURI = uri.trim();
  const lastSlashIndex = trimmedURI.lastIndexOf('/');
  if (lastSlashIndex === -1 || lastSlashIndex === trimmedURI.length - 1) {
    return trimmedURI;
  }
  const lastPart = trimmedURI.substring(lastSlashIndex + 1)
  return lastPart;
}

/**
 * Handle get/set APIs
 * To upload files via curl you can use:
 * `curl -iv http://localhost:80/kv -F cert=@njs/http/certs/ca/intermediate/certs/www.example.com.cert.pem -F key=@njs/http/certs/ca/intermediate/private/www.example.com.key.pem`
 * then read it back: `curl http://localhost/kv/www.example.com.cert.pem`
 *
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 */
function kv(r) {
  const zone = r.variables['shared_dict_zone_name'];
  const prefix = r.variables['cert_folder'] || '/etc/nginx/certs/';
  const cache = zone && ngx.shared && ngx.shared[zone];

  if (r.method === `GET`) {
    const p = keyFromURI(r.uri);
    if (!p) {
      r.return(400, 'No key found');
      return
    }
    const path = joinPaths(prefix, p)
    const key = ['certs', path].join(':');;
    r.log(`Reading from cache ${key}`)
    const data = cache && cache.get(key);;
    if (!data) {
      r.return(404, 'Data not found in the cache')
      return;
    }
    r.return(200, data);
  } else if (r.method === 'POST') {
    const requestBody = r.requestText;
    if (!requestBody || requestBody.length === 0) {
      r.return(400, 'No file uploaded');
      return;
    }
    // Parse the request body to extract file information
    var boundary = r.headersIn['Content-Type'].match(/boundary=(.*)/)[1];
    var parts = requestBody.split('--' + boundary);
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i].trim();
      if (part.indexOf('Content-Disposition') !== -1) {
        var filename = part.match(/filename="(.*)"/);
        if (filename) {
          // The file content is available in the part after the blank line (\r\n\r\n)
          var fileContent = part.split('\r\n\r\n')[1];
          let path = joinPaths(prefix, filename[1]);
          r.log(`Saving file: ${filename[1]}, Size: ${fileContent.length}, Path: ${path}`);
          try {
            fs.writeFileSync(path, fileContent);
            r.log(`Wrote to file. Path: ${path}`);
            if (cache) {
              const key = ['certs', path].join(':');
              cache.set(key, fileContent);
              r.log(`Wrote to cache. Key: ${key}`);
            }
          } catch (err) {
            r.return(500, `Error saving ${err}`);
            return;
          }
        }
      }
    }
    r.return(201);
  } else {
    r.return(405, 'Method Not Allowed');
    return;
  }
}

/**
 * Clear Cache
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 */
function clear_cache(r) {
  const zone = r.variables['shared_dict_zone_name']
  const cache = zone && ngx.shared && ngx.shared[zone]
  if (cache) {
    cache.clear()
    r.log(`cleared ${zone}`)
  }
  r.return(200)
}

/**
 * Info handler to return request info
 * @param {NginxHTTPRequest} r - The Nginx HTTP request object.
 */
function info(r) {
  const out = {
    request: r,
    variables: {
      shared_dict_zone_name: r.variables['shared_dict_zone_name'],
      dynamic_ssl_cert: r.variables['dynamic_ssl_cert'],
      dynamic_ssl_key: r.variables['dynamic_ssl_key'],
      cert_folder: r.variables['cert_folder'],
      ssl_alpn_protocol: r.variables['ssl_alpn_protocol'],
      ssl_client_fingerprint: r.variables['ssl_client_fingerprint'],
      ssl_session_id: r.variables['ssl_session_id'],
      ssl_server_name: r.variables['ssl_server_name'],
      ssl_protocol: r.variables['ssl_protocol '],
      hostname: r.variables['hostname'],
      host: r.variables['host'],
    }
  }
  r.return(200, JSON.stringify(out))
}

export default {
  js_cert,
  js_key,
  kv,
  clear_cache,
  info
}
