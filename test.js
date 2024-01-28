const crypto = require('crypto');

const password = 'fidelio';
const algorithm = 'aes-128-cbc';

function encrypt(password, text) {
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(16)], 16);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + encrypted.toString('hex');
}

function decrypt(password, text) {
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(16)], 16);
    const iv = Buffer.from(text.substring(0, 32), 'hex');
    const encryptedText = Buffer.from(text.substring(32), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const encryptedText = encrypt(password, 'albertone')
console.log(encryptedText);
const decryptedText = decrypt(password, encryptedText)
console.log(decryptedText);