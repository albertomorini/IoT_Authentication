const http = require("https");
const fs = require("fs");
const port = 1999;
const cyper = require("./cypher");



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
    req.on("end",()=>{
        body= JSON.parse(body); //FOR THIS PROJECT WE WILL OPERATE ONLY WITH HTTPS POST METHOD (not GET/PUT/DELETE and so)
        console.log(body);


        if(req.url=="first"){
            let publicClient = body.publicKey;
            encodedMessage = cyper.decrypt("ECC",publicClient,body.msg)
        }
       
    });

}).listen(port);
console.log("Server started at port: "+port);