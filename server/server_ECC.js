const http = require("https");
const fs = require("fs");
const port = 1999;
const cyper = require("./cypher_ECC");



var eccrypto = require('eccrypto'); // for Elliptic curve cryptography 

const privateServer = eccrypto.generatePrivate();
const publicServer = eccrypto.getPublic(privateServer);



////////////////////////////////////////////
// SERVER SIDE -- HTTP STUFF
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
    req.on("end", async ()=>{
        body= JSON.parse(body); //FOR THIS PROJECT WE WILL OPERATE ONLY WITH HTTPS POST METHOD (not GET/PUT/DELETE and so)


        if(req.url=="/getCertificate"){
            sendResponse(res,200,{
                "pk":
                Buffer.from(publicServer).toString("base64")
            })
        }

        if(req.url=="/getPrivate"){
            sendResponse(res,200,{
                "pk":
                Buffer.from(privateServer).toString("base64")
            })
        }



        if(req.url=="/first"){          
            let secret = await cyper.eccDecrypt(privateServer,body.cifrato);
            console.log(secret);
        }
       

        if(req.url=="/ECCDH"){
            let publicClient = body.pubKey;
            let sharedK = await eccrypto.derive(privateServer, Buffer.from(publicClient,"base64"));

            console.log(sharedK);
            sendResponse(res,200,{
                pubKey: Buffer.from(publicServer).toString("base64")
            });
        }



    });

}).listen(port);
console.log("Server started at port: "+port);
// console.log(Buffer.from(publicServer).toString("base64"));
// console.log(publicServer.toString('hex').match(/../g).join(' '));

