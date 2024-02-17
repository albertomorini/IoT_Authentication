process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // TO TRUST SELF SIGNED
const fs = require("fs");

const cyper = require("./cypher.js"); // my local class to execute the encryptions algorithms
const eccrypto = require('eccrypto'); // for Elliptic curve cryptography 

const privateKey = eccrypto.generatePrivate(); // "private key" of ECC DH
const publicKey = eccrypto.getPublic(privateKey); // public key of ECC DH 

const alg = "AES128" // algorithm used to encrypt

const DEVICE_ID = "toyota";
const KEYS = fs.readFileSync("./secretVault.txt");;


///////////// -- HTTP STUFF
/**
 * Execute a post request to the server
 * @param {string} path url path
 * @param {JSON} body the data
 * @returns {promise} response in JSON format
 */
function doPostRequest(path, body) {
    return fetch("https://localhost:1999/" + path, {
        method: "POST",
        mode: "cors",
        body: JSON.stringify(body),
        headers: { "Content-type": "JSON/Application", "Access-Control-Allow-Origin": "*" }
    }).then(res => res.json()).catch(err => {
        console.log(err);
    })
}



///////////////////////// -- PAPER STUFF
/**
 * @param {int} max 
 * @returns a random integer between 0 and max 
 */
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
//////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////
/**
 * EXTRA PAPER: send a private message to the server, encoded by default by AES 256 (by assumption)
 * @param {int} sessionID the session ID
 * @param {string} psw the shared password key
 * @param {string} message our secret message
 */
function sendData(sessionID, psw,message){
    return doPostRequest("data",{
        alg: alg,
        deviceID: DEVICE_ID,
        sessionID: sessionID,
        message: cyper.encrypt("AES256",psw,message)
    }).then(res=>{
       return console.log("\t\t --- Server data --- \n > "+ res.msg);
    });
}


//STEP 3
function thirdStep(M3, sessionID,k2,t1) {
    return doPostRequest("third", { //send the challenge M3
        alg: alg,
        M3: M3,
        deviceID: DEVICE_ID,
        sessionID: sessionID
    }).then(async res => { //receive the challenge M4

        console.time("fourthStep")
        let M4= cyper.decrypt(
            alg
            ,
            k2^t1, //XOR
            res
        );
        M4 = JSON.parse(M4) 
        console.timeEnd("fourthStep"); //stop timer, we have the session key

        console.log("Session t: "+ (t1^parseInt(M4.t2))); //t1 xor t2
        
        let secretMessage = "from_deviceID:" + DEVICE_ID + "w/:paperIoTAuth_{pulpfiction_killbill_reservoirdogs}"
        return await sendData(sessionID, (t1 ^ parseInt(M4.t2)),secretMessage)
    })

}

// STEP 1: client start the authentication 
function firstStep(deviceID, sessionID) {

    return doPostRequest("first", { //do the first step (sending deviceID,sessionID)
        alg: alg, //AES128 or AES256
        deviceID: deviceID,
        sessionID: sessionID
    }).then(async res => { // receive the first challenge "M2"

        console.time("secondStep")
        let k1 = ExecXOR(res.indexKeys); //to the xor of C1(=indexKeys)

        let t1 = GetRandomInt();
        let C2 = GetIndexKeys();
        let r2 = GetRandomInt();
        //create the challenge M3
        let M3 = cyper.encrypt(alg,k1,
            JSON.stringify({
                r1: res.randomOne,
                t1: t1,
                C2: C2,
                r2: r2
            })
        );
        let k2= ExecXOR(C2);
        console.timeEnd("secondStep")
        return await thirdStep(M3, sessionID,k2,t1); //sending to server the third step

    })

}


////////////////////////////////////////////////////////////

// Session key generated via Elliptic Curve - Diffie Hellman
async function doECCDH(deviceID, sessionID){
    
    console.time("ECC_KeyExc")
    // share the client's public key to server - as a replay, the public key of the server
    let publicKeyServer = await doPostRequest("ECCDH", { 
        pubKey: Buffer.from(publicKey, "base64"), //NB: encrypt via Base64 thus to not lose or change data on Buffer
        deviceID: deviceID,
        sessionID: sessionID
    });
    let sharedK = await eccrypto.derive(privateKey, Buffer.from(publicKeyServer.pubKey, "base64")); //derive the shared key
    console.timeEnd("ECC_KeyExc"); //end timer, we have derived the session key
    
    console.log("ECCDH secret shared key is: "+sharedK.toString("hex"));

    let secretMessage = "from_deviceID:" + DEVICE_ID + "_w/:ECCDH_{akira_berserk_invincible}";
    return await sendData(sessionID, sharedK, secretMessage); //shared key is ok --> send data (secret message)
}


/**
 * execute the key exchanges several times
 * @param {int} cycles numbers of test
 */
async function start(cycles){

    console.log("________________________________________________________");
    console.log("\t Test "+ cycles+ " time the algorithm of the paper");
    for (let i = 0; i < cycles; i++) {
        await firstStep(DEVICE_ID, i);
    }
    console.log("________________________________________________________");
    console.log("\n\n\nlet's test "+ cycles+ " time the ECC_DH key exchange");
    for (let i = 0; i < cycles; i++) {
        await doECCDH(DEVICE_ID, i)
    }
}

start(10)