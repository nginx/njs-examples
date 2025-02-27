async function getKey() {
    const pem = atob(process.env.PUBLIC_KEY
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, ''));

    const format = 'spki';
    const keyData = Uint8Array.from(pem, (char) => char.charCodeAt(0)).buffer;
    const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    const isExtractable = true;
    const keyUsages = ['verify'];
    
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    return crypto.subtle.importKey(
        format,         // Subject Public Key Info
        keyData,        // Convert to 8-bit unsigned Buffer Array
        algorithm,      // RS256 algorithm
        isExtractable,  // Extract key
        keyUsages       // Key actions
    );
}

function base64UrlDecode(input) {
    const padding = '='.repeat((4 - (input.length % 4)) % 4);

    return atob(input + padding);
}

function decodeBase64Url(base64Url) {
    return base64Url
        .replace(/-/g, '+')
        .replace(/_/g, '/');
}

async function verify(token) {
    const components = token.split('.');
    const headerB64Url = components[0];
    const payloadB64Url = components[1];
    const signatureB64Url = components[2];

    const isJWT = (headerB64Url && payloadB64Url && signatureB64Url);
    if (!isJWT) {
        console.error('Invalid JWT Format');
        
        return { isValid: false };
    }

    // Decode base64URL to Base64
    const headerBase64 = decodeBase64Url(headerB64Url);
    const payloadBase64 = decodeBase64Url(payloadB64Url);
    const signatureB64 = decodeBase64Url(signatureB64Url);

    // Decode the Base64 bytes into utf-8
    const header = JSON.parse(atob(headerBase64));
    const payload = JSON.parse(atob(payloadBase64));
    const signature = base64UrlDecode(signatureB64);

    const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    const key = await getKey();
    const signatureBase = Uint8Array.from(signature, (char) => char.charCodeAt(0));
    const signingInput = new TextEncoder().encode(`${headerB64Url}.${payloadB64Url}`);

    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
    const isValid = await crypto.subtle.verify(
        algorithm,      // RSA256 algorithm
        key,            // CryptoKey
        signatureBase,  // Convert base64 to 8-bit unsigned
        signingInput    // Recreate the unsigned data to be verified (header.payload)
    );

    return { header, payload, isValid };
}

export default { verify }