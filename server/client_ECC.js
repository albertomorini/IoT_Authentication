process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // TRUST SELF SIGNED

var eccrypto = require('eccrypto'); // for Elliptic curve cryptography 
var cyper = require("./cypher_ECC");

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


const privateServer = eccrypto.generatePrivate();
const publicClient = eccrypto.getPublic(privateServer);

async function x(){
    let xa = await doPostRequest("getCertificate",{x:"s"})

    // console.log(Buffer.from(xa.pk, "base64").toString('hex').match(/../g).join(' '));
    let cifrato = await cyper.eccEncrypt(Buffer.from(xa.pk, "base64"),"ALBY FUNZIONAAA!!!!");


    eccrypto.derive(privateServer,(Buffer.from(xa.pk, "base64"))).then(shared=>{
        console.log(shared);
    })


    // let private = await doPostRequest("getPrivate",{x:"s"});

    // console.log(Buffer.from(private.pk,"base64"));
    // let clearly = await cyper.decrypt("ECC", Buffer.from(private.pk, "base64"), cifrato);
     console.log(cifrato);

    let xb = await doPostRequest("first",{
        "cifrato": cifrato,
    });

}


async function doECCDH(){
    let publicKeyServer = await doPostRequest("ECCDH",{pubKey:Buffer.from(publicClient,"base64")});
    
    let sharedK = await eccrypto.derive(privateServer, Buffer.from(publicKeyServer.pubKey,"base64"));
    console.log(sharedK);


}


doECCDH()

 //TODO: comment line 190 on browser.js

