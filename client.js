const crypto = require('crypto');
const algorithm = 'aes-128-cbc';


const DEVICE_ID = "toyota";
const KEYS = [10000, 20001, 30002, 40003, 50004, 60005];


///////////// -- HTTP STUFF

function doPostRequest(path, body) {
    return fetch("http://localhost:1999/" + path, {
        method: "POST",
        mode: "cors",
        body: JSON.stringify(body),
        headers: { "Content-type": "JSON/Application", "Access-Control-Allow-Origin": "*" }
    }).then(res => res.json()).catch(err => {
        console.log(err);
    })
}

/////////// -- UTILITY



function AES_Encrypt(password, text) {
    password = password.toString();
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(16)], 16);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + encrypted.toString('hex');
}

function AES_Decrypt(password, text) {
    password = password.toString();
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(16)], 16);
    const iv = Buffer.from(text.substring(0, 32), 'hex');
    const encryptedText = Buffer.from(text.substring(32), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}




///////////////////////// -- PAPER STUFF

function GetRandomInt(max = 256) {
    return Math.floor(Math.random() * max);
}

function GetIndexKeys() {
    let indexes = [];
    for (let i = 0; i < KEYS.length - 1; i++) {
        indexes.push(GetRandomInt(KEYS.length));
    }
    return indexes;
}

function ExecXOR(array) {
    let res = 0;
    array.map(s => {
        res = res ^ KEYS[s];
    });
    return res;
}
//////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

//STEP 3
function resolveChallenge(M3, sessionID,k2,t1) {
    //TODO: ask for DeviceID and sessionID 
    //TODO: ask even for resend these infos
    doPostRequest("third", {
        M3: M3,
        deviceID: DEVICE_ID,
        sessionID: sessionID
    }).then(res => {
        console.log("M4: "+res);

        let M4= AES_Decrypt(
            k2^t1,
            res
        );
        console.log(M4);
        M4 = JSON.parse(M4)
        console.log("Session t: "+ (t1^parseInt(M4.t2)));

        
    })

}

function Auth2Server(deviceID, sessionID) {

    doPostRequest("first", {
        deviceID: deviceID,
        sessionID: sessionID
    }).then(res => {

        console.log(res);

        let k1 = ExecXOR(res.indexKeys);
        console.log(k1);

        let t1 = GetRandomInt();
        let C2 = GetIndexKeys();
        let r2 = GetRandomInt();
        let M3 = AES_Encrypt(k1,
            JSON.stringify({
                r1: res.randomOne,
                t1: t1,
                C2: C2,
                r2: r2
            })
        );
        let k2= ExecXOR(C2);
        resolveChallenge(M3, sessionID,k2,t1);
    })

}


Auth2Server(DEVICE_ID, 1);