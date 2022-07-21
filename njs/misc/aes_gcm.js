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

	const alg = { name: 'AES-GCM', iv: Buffer.from(value.iv, 'base64') };
	const sha256 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key_in));
	const key = await crypto.subtle.importKey('raw', sha256, alg, false, ['decrypt']);

	const decrypt = await crypto.subtle.decrypt(alg, key, Buffer.from(value.cipher, 'base64'));
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
