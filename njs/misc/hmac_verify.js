async function getKey() {
    const format = 'raw'
    const keyData = new TextEncoder().encode(process.env.SECRET);
    const algorithm = { name: 'HMAC', hash: 'SHA-1' };
    const isExtractable = false;
    const keyUsages = ['sign'];

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    return crypto.subtle.importKey(
        format,         // RAW
        keyData,        // Convert to 8-bit unsigned Buffer Array
        algorithm,      // HMAC algorithm
        isExtractable,  // Extract key
        keyUsages       // Key actions
    );
}

async function generateHmac(message) {
    const algorithm = 'HMAC';
    const key = await getKey();
    const data = new TextEncoder().encode(message);

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
    const signature = await crypto.subtle.sign(
        algorithm,  // HMAC algorithm
        key,        // CryptoKey
        data        // Convert to 8-bit unsigned Buffer Array
    );

    return btoa(Array
        .from(new Uint8Array(signature))
        .map(b => String.fromCharCode(b))
        .join('')
    );
}

function parseToken(token) {
    const parsedToken = token
        .replace(/-/g, "=")
        .replace(/_/g, "+");

    return {
        digest: parsedToken.substring(0, 28),
        iv: parsedToken.substring(28, 52),
        encrypted: parsedToken.substring(52),
    };
}

async function isSigned(token) {
    const parsedToken = parseToken(token);
    const hmac = await generateHmac(parsedToken.encrypted)

    return (parsedToken.digest === hmac);
}