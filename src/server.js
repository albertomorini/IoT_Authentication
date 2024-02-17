const http = require("https");
const fs = require("fs");
const port = 1999; // server port
const cyper = require ("./cypher.js"); // my local class to execute the encryptions algorithms
const eccrypto = require('eccrypto'); // for Elliptic curve cryptography 


const privateKey = eccrypto.generatePrivate(); // "private key" of ECC DH
const publicKey = eccrypto.getPublic(privateKey); // public key of ECC DH 

const IOT_UIDS=["toyota","kia","mazda","jaguar"]; //UID of devices, will ignored potential message of unknown IoT device
const KEYS = fs.readFileSync("./secretVault.txt");

let sessionsID ={} //this set will used to store the generated keys for each session-client --> not specified in the paper, but server talks with several clients, so we can't use a unique variable to store the keys generated (k2,k3.. see on "third" step)


////////////////////////////-- PAPER STUFF

/**
 * @param {int} max 
 * @returns a random integer between 0 and max 
 */
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
/**
 *  execute the XOR of an array
 * @param {Array} array 
 * @returns {int} the value
 */
function ExecXOR(array) {
    let res = 0;
    array.map(s => {
        res = res ^ KEYS[s];
    });
    return res;
}

/**
 * FIRST STEP: client has contacted the server for the first time
 * @param {Object} body the HTTP body request
 */
function firstStep(res,body){
    //check if the DeviceID is known 
    if (IOT_UIDS.includes(body.deviceID)) {
        let M2 = {}; //generate the challenge M2

        let C1 = GetIndexKeys();
        let r1 = GetRandomInt();
        M2.indexKeys = C1;
        M2.randomOne = r1;
        sessionsID[body.sessionID + body.deviceID] = C1; //Save the session to individuate which index we sent to the IOT client before
        sendResponse(res, 200, M2);

    } else {
        sendResponse(res, 401);
    }
}

function thirdStep(res,body){
    //check if the DeviceID is known
    if (IOT_UIDS.includes(body.deviceID)) {
        let C1 = sessionsID[body.sessionID + body.deviceID]; //retrieve C1 thus to have k1
        let k1 = ExecXOR(C1);

        let tmpM3 = cyper.decrypt(body.alg, k1, body.M3); //decrypt challenge M3 with k1

        tmpM3 = JSON.parse(tmpM3); //instead of sentinel, we use JSON, so parse it

        let k2 = ExecXOR(tmpM3.C2);
        let t2 = GetRandomInt();
        //create now the M4 challenge
        let M4 = cyper.encrypt(
            body.alg,
            k2 ^ tmpM3.t1, //XOR
            JSON.stringify({
                r2: tmpM3.r2,
                t2: t2
            })
        );
        console.log("Session t: " + (tmpM3.t1 ^ t2));
        sendResponse(res, 200, M4)

        sessionsID[body.sessionID + body.deviceID] = (tmpM3.t1 ^ t2); //update the session key with the final one
    }else {
        sendResponse(res,401)
    }
}

/**
 * EXTRA PAPER: client will send a custom string, we will return the uppercase of that
 * @param {Object} body 
 */
function dataReceived(res,body){
    console.log(body);
    let sessionKey = sessionsID[body.sessionID + body.deviceID]; //get the encryption shared key (indipendent by algorithm (ECC or so))
    let secretMessage = cyper.decrypt("AES256",sessionKey, body.message); //ASSUMPTION: data message is encrypted via AES256 in every scenario
    console.log(secretMessage);
    sendResponse(res,200,{"msg":secretMessage.toUpperCase()});
}

////////////////////////////////////////////
// HTTP STUFF
/**
 * Do the HTTP response
 * @param {Object} res HTTPS response object
 * @param {int} status like 200/500
 * @param {Object} body body of response
 * @param {String} contentType the content type of our response
*/
function sendResponse(res, status, body = null, contentType = "application/json") {
    res.writeHead(status, { "Content-type": contentType, "Access-Control-Allow-Origin": "*" })
    res.write(JSON.stringify(body));
    res.end();
}

const options = {
    key: fs.readFileSync("./x509/key.pem"),
    cert: fs.readFileSync("./x509/cert.pem")
}

http.createServer(options,(req,res)=>{

    let body=""
    req.on("data",(chunk)=>{
        body+=chunk;
    });
    req.on("end",async ()=>{

        try {
            body= JSON.parse(body); //FOR THIS PROJECT WE WILL OPERATE ONLY WITH HTTPS POST METHOD (not GET/PUT/DELETE and so)
        } catch (error) {
            console.log("No body");
        }

        //Paper's authentication
        if(req.url=="/first"){  //first step of the handshake
            firstStep(res,body)
        }

        if(req.url=="/third"){ //third step of the handshake
            thirdStep(res,body);
        }

        ////////////////////////////////////////////////

        //ECC with Diffie-Hellman
        if (req.url =="/ECCDH"){
            let publicClient = body.pubKey; // get the public key of the client
            let sharedK = await eccrypto.derive(privateKey, Buffer.from(publicClient, "base64")); //derive the shared key
            console.log("ECCDH secret shared key is: "+ sharedK.toString("hex"));
            sessionsID[body.sessionID + body.deviceID] = (sharedK) // store the shared key - will needed to decode the secret message on /data

            //reply to client with the public key of the server
            sendResponse(res, 200, {
                pubKey: Buffer.from(publicKey).toString("base64") //NB: encrypt via Base64 thus to not lose or change data on Buffer
            });
        }

        if(req.url=="/data"){ //EXTRA PAPER: client send a secret message and we'll return the upper case of that
            dataReceived(res,body)
        }

    });

}).listen(port);
console.log("Server started at port: "+port);
