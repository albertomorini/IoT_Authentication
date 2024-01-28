const http = require("https");
const fs = require("fs");
const port = 1999;
const crypto = require('crypto')
const algorithm = 'aes-128-cbc';


const IOT_UIDS=["toyota","kia","mazda","jaguar"];
const KEYS = [10000,20001,30002,40003,50004,60005];

let sessionsID ={}



////////////////////////////////////////////
////////////////////////////////////////////
// -- HTTP STUFF
/**
 * Do the HTTP response
 * @param {Object} res HTTPS response object
 * @param {int} status like 200/500
 * @param {Object} body body of response
 * @param {String} contentType the content type of our response
*/
function sendResponse(res, status, body=null, contentType = "application/json") {
    res.writeHead(status, { "Content-type": contentType, "Access-Control-Allow-Origin": "*" })
    res.write(JSON.stringify(body));
    res.end();
}
/////////////////////////////// -- UTILITY

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

////////////////////////////-- PAPER STUFF

function GetRandomInt(max=256) {
    return Math.floor(Math.random() * max);
}

function GetIndexKeys(){
    let indexes = [];
    for(let i=0; i<KEYS.length-1; i++){
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

////////////////////////////////////////////
////////////////////////////////////////////
// SERVER SIDE
function decryptX509(password, text) {
    let algorithm = "aes-256-cbc"
    password = password.toString();
    const key = Buffer.concat([Buffer.from(password), Buffer.alloc(32)], 32);
    const iv = Buffer.from(text.substring(0, 48), 'hex');
    const encryptedText = Buffer.from(text.substring(32), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}


const options = {
    cert: fs.readFileSync("./x509/cert.pem"),
    key: crypto.createPrivateKey({
        'key': fs.readFileSync("./x509/key.pem"),
        'format': 'pem',
        'type': 'pkcs8',
        'cipher': 'aes-256-cbc',
        'passphrase': 'fidelio'
    }).toString()
}


http.createServer(options,(req,res)=>{

    let body=""
    req.on("data",(c)=>{
        body+=c;
    });
    req.on("end",()=>{
        body= JSON.parse(body);
        console.log(body);

        if(req.url=="/first"){
            //check if the DeviceID is well-formed 
            if(IOT_UIDS.includes(body.deviceID)){
                let M2= {};

                let C1 = GetIndexKeys();
                let r1 = GetRandomInt();
                M2.indexKeys=C1;
                M2.randomOne = r1;
                sessionsID[body.sessionID+body.deviceID]= C1; //Save the session to individuate which index we sent to the IOT client before
                sendResponse(res,200,M2);

            }else{
                sendResponse(res,401);
            }
        }

        if(req.url=="/third"){
            let C1= sessionsID[body.sessionID+body.deviceID]; //retrieve C1 thus to have k1
            let k1 = ExecXOR(C1);
            console.log("k1:: "+k1);
            let tmpM3 = AES_Decrypt(k1,body.M3);
            console.log(tmpM3);
            //TODO: ask if ok sentinel char ~~≥ JSON
            tmpM3 = JSON.parse(tmpM3);
            
            let k2 = ExecXOR(tmpM3.C2);


            let t2= GetRandomInt();
            let M4 = AES_Encrypt(
                k2^tmpM3.t1,
                JSON.stringify({
                    r2: tmpM3.r2,
                    t2: t2
                })
            );
            console.log("Session t: "+(tmpM3.t1^t2));
            sendResponse(res,200,M4)

            sessionsID[body.sessionID + body.deviceID] = (tmpM3.t1 ^ t2)

        }
        if(req.url=="/data"){
            let sessionKey = sessionsID[body.sessionID+body.deviceID];
            let x = AES_Decrypt(sessionKey,body.message);
            console.log(x);
        }

    });

}).listen(port);