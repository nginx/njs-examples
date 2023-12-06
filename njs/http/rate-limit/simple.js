const defaultResponse = "0";

/**
 * Applies rate limiting logic for the request.
 *
 * @param {Object} r - The request object.
 * @returns {string} - The retry-after value in seconds as a string. '0' means no reate limit.
 */
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
        r.log(`ratelimit: setting initial value for ${key}`);
        requestData = { timestamp: now, count: 1 }
        kv.set(key, JSON.stringify(requestData));
        return defaultResponse;
    }
    try {
        requestData = JSON.parse(requestData);
    } catch (e) {
        r.log(`ratelimit: failed to parse value for ${key}`);
        requestData = { timestamp: now, count: 1 }
        kv.set(key, JSON.stringify(requestData));
        return defaultResponse;
    }
    if (!requestData) {
        // remember the first request
        r.log(`ratelimit: value for ${key} was not set`);
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
