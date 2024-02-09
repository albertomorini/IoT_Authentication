process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // TRUST SELF SIGNED

var eccrypto = require('eccrypto'); // for Elliptic curve cryptography 
var cyper = require("./cypher");

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

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
        sendData(sessionID, (t1 ^ parseInt(M4.t2)))
        
    })

}

const privateClient = eccrypto.generatePrivate();
const publicClient = eccrypto.getPublic(privateClient);

async function Auth2Server(deviceID, sessionID) {

    let x = await cyper.encrypt("ECC",privateClient,"Alby");
    console.log(x);
    doPostRequest("first", {
        publicKey: publicClient,
        msg: x 
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


Auth2Server("DEVICE_ID", 1);