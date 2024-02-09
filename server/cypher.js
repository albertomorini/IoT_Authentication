const crypto = require('crypto')
var eccrypto = require('eccrypto'); // for Elliptic curve cryptography 


function AES128_Encrypt(password, text) {
    const algorithm = 'aes-128-cbc';
    password = password.toString();
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(16)], 16);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + encrypted.toString('hex');
}

function AES128_Decrypt(password, text) {
    const algorithm = 'aes-128-cbc';
    password = password.toString();
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(16)], 16);
    const iv = Buffer.from(text.substring(0, 32), 'hex');
    const encryptedText = Buffer.from(text.substring(32), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

function AES256_Encrypt(password, text) {
    const algorithm = 'aes-256-ctr';
    const key = Buffer.concat([Buffer.from(password.toString()), Buffer.alloc(32)], 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + encrypted.toString('hex');
}

function AES256_Decrypt(password, text) {
    const algorithm = 'aes-256-ctr';
    const key = Buffer.concat([Buffer.from(password.toString()), Buffer.alloc(32)], 32);
    const iv = Buffer.from(text.substring(0, 32), 'hex');
    const encryptedText = Buffer.from(text.substring(32), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

function ECC_Encrypt(publicKey,text){
    return eccrypto.encrypt(publicKey, Buffer.from(text))
}

function ECC_Decrypt(publicKey, encrypted){
    return eccrypto.decrypt(publicKey, encrypted).then(async (plaintext) => {
        let x =  await plaintext.toString()
        return x
    });
}


var privateKeyA = eccrypto.generatePrivate();
var publicKeyA = eccrypto.getPublic(privateKeyA);

let x = ECC_Encrypt(publicKeyA,"alberto");
x.then(async res=>{
    let x = await ECC_Decrypt(privateKeyA, res)
})


function decrypt(alg,password,message){
    if(alg=="AES128"){
        return AES128_Decrypt(password,message);
    }else if(alg=="AES256"){
        return AES256_Decrypt(password,message);
    }else if(alg=="ECC"){
        return ECC_Decrypt(password,message);
    }
}

function encrypt(alg,password,message){
    if (alg == "AES128") {
        return AES128_Encrypt(password,message)
    } else if (alg == "AES256") {
        return AES256_Encrypt(password,message)
    } else {
        return ECC_Encrypt(password,message)
    }
}



module.exports={
    encrypt: encrypt,
    decrypt: decrypt
}