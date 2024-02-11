process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // TO TRUST SELF SIGNED

const cyper = require("./cypher.js"); // my local class to execute the encryptions algorithms
const eccrypto = require('eccrypto'); // for Elliptic curve cryptography 

const privateKey = eccrypto.generatePrivate(); // "private key" of ECC DH
const publicKey = eccrypto.getPublic(privateKey); // public key of ECC DH 

const alg = "AES256" // algorithm used to encrypt

const DEVICE_ID = "toyota";
const KEYS = [67713524793335768731, 26747432817864159792, 33761647468658116635, 93417431227443688669, 63125331514238389471, 26683246793273822124, 94653923953817875994, 29275399767855378451, 23641444157425921566, 57726129418776771567, 68792178625717166258, 26338843413942281637, 74937745895421198991, 22445648465164535287, 79569134286248244253, 14859681953857237515, 88715652531535229429, 62488235145442362484, 23171357938453614686, 25118343271271861765, 65293955717557159512, 93937467567783897429, 27179835434875614278, 66658626239822781718, 89863339227475756643, 15739456587776434458, 39927369384393946832, 76131912144735987798, 25525629613182819659, 72647927647393673432, 55585699489176951125, 22734888351528144767, 13123965956568642845, 16439849236475932768, 57995575354637967754, 56663565396681484699, 82866954454385871274, 81382565545564429691, 37862398247896694485, 69369787441231173467, 93127891984894436856, 38367611861144188914, 82666585552742959612, 66729855182639282134, 38295658466928411124, 94419389579874397587, 54586249641926651216, 46729682482192297129, 94951388484493994449, 58812368546954827315, 37747983472818756835, 73625135942421659271, 52999543827618989194, 15581565998947459164, 44182449562475249851, 64531395365674476326, 16384612565424345672, 34959461375786634324, 54247575151237888955, 42396849518899484393, 86587137465138923253, 98783112977323946521, 16947813615192365562, 31754794754458455991, 12494284687297491995, 99818171774523698752, 14645791337873323554, 31625252163946989663, 83441212862121827534, 14164467182391918356, 61556486554899283479, 58929792749198137369, 91359194697938253583, 23331684513988845152, 98431669136182639385, 69649461224311753273, 45845398916746498463, 85273717141712966826, 21363383257185272791, 84327468588598749334, 27613363864244155882, 52963392933792462213, 88833566544772411327, 56269616585363257623, 44496465598346176988, 86947372916669222392, 68531356858871984588, 25958351768685638613, 83836744789984852747, 34462641272459865435, 34222273689134921665, 74365782333445622746, 76723868929932228639, 83526226297621212989, 96635395913782191299, 25378635659328831398, 22393183358115353633, 92723297565393648825, 11769134424275971157, 49699516423126642337, 33443389428284411556, 83346592327332638876, 26331995984369586286, 45641737782178788586, 77799163325587641527, 79313877934336727977, 85214685452993669725, 47742229966484188555, 53223468197229373733, 36181795766845859478, 29418319459933699319, 44696773536515448862, 35987164794639672782, 66687263731781776158, 32973888423991794919, 14844349839395673246, 12991562484682933434, 63563261313629873318, 17951965764714747254, 48999225111646289124, 88383397566525628448, 81723363471445626482, 83872725193355996893, 17595863174523848771, 48386637147997876286, 68654354381495847332, 12416683384633448381, 99681239211176714311, 34957836243389817431, 24221911443794224523, 96258283653354966896, 57175131212877468422, 39391116334482471922, 45157663175188658245, 79536543937937152253, 57838458879124933912, 34838892295863829374, 51432164382518611513, 21183879149689833826, 55742196553663158397, 73228683852426211177, 26581191973416754151, 55732358516377771581, 23177776429519174365, 64542532195164934653, 83953263924599522923, 19721896655967611127, 75541663686389765652, 44399721384997196134, 24576452134811818956, 85459624348981539659, 73774316275883355135, 13494837984378345251, 39585533923644513971, 64819468715874336919, 83261719758963754224, 22354552517449758426, 87355238869769121777, 43664816811469571484, 97518687629354935431, 46757614589653762768, 69588678629665665884, 48355392716859788876, 95891563567862648564, 61378398282193579141, 17735746739271492937, 33837513364792897223, 75433977351222348398, 21764751167812382978, 31625846126357247849, 69259169286413346254, 22776966992597254624, 36815687566189162393, 95973678913422135614, 58459681879997793798, 73728168213353357178, 79141437279759155589, 99645582286518196715, 76165692144381765438, 98954476718129591787, 71988764894286214331, 78269389474283378754, 61265693927245665339, 75492484978355533657, 29232299849158121327, 53795518984955744949, 36328773637188111381, 67369989893264762413, 53412971666678685832, 93271386591963572184, 12342856826552281921, 64521421997728495415, 34376616816363945196, 29459344656951346824, 77174224116591438375, 18515578825592665368, 21495371379383362445, 69235152529665753964, 47387693684136415169, 26586956118654864819];


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
    doPostRequest("data",{
        alg: alg,
        deviceID: DEVICE_ID,
        sessionID: sessionID,
        message: cyper.encrypt("AES256",psw,message)
    }).then(res=>{
        console.log("SERVER RESPONSE: "+ res.msg);
    });
}


//STEP 3
function resolveChallenge(M3, sessionID,k2,t1) {
    //TODO: ask for DeviceID and sessionID 
    //TODO: ask even for resend these infos
    doPostRequest("third", {
        alg: alg,
        M3: M3,
        deviceID: DEVICE_ID,
        sessionID: sessionID
    }).then(res => {
        console.log("M4: "+res);

        console.time("fourthStep")
        let M4= cyper.decrypt(
            alg
            ,
            k2^t1,
            res
        );
        console.log(M4);
        M4 = JSON.parse(M4)
        console.log("Session t: "+ (t1^parseInt(M4.t2)));
        
        let secretMessage = "from_deviceID:" + deviceID + "w/:paperIoTAuth_pulpfiction_killbill_reservoirdogs"
        sendData(sessionID, (t1 ^ parseInt(M4.t2)),secretMessage)
        console.timeEnd("fourthStep")
    })

}

function Auth2Server(deviceID, sessionID) {

    doPostRequest("first", {
        alg: alg,
        deviceID: deviceID,
        sessionID: sessionID
    }).then(res => {

        console.log(res);

        console.time("secondStep")
        let k1 = ExecXOR(res.indexKeys);
        console.log(k1);

        let t1 = GetRandomInt();
        let C2 = GetIndexKeys();
        let r2 = GetRandomInt();
        let M3 = cyper.encrypt(alg,k1,
            JSON.stringify({
                r1: res.randomOne,
                t1: t1,
                C2: C2,
                r2: r2
            })
        );
        let k2= ExecXOR(C2);
        resolveChallenge(M3, sessionID,k2,t1);
        console.timeEnd("secondStep")

    })

}


console.time("globalSW");
Auth2Server(DEVICE_ID, 1);
console.timeEnd("globalSW")

////////////////////////////////////////////////////////////

/**
 * 
 * @param {*} deviceID 
 * @param {*} sessionID 
 */
async function doECCDH(deviceID, sessionID){
    // share the public key to the server - as a replay, the public key of the server
    let publicKeyServer = await doPostRequest("ECCDH", { 
        pubKey: Buffer.from(publicKey, "base64"),
        deviceID: deviceID,
        sessionID: sessionID
    });
    let sharedK = await eccrypto.derive(privateKey, Buffer.from(publicKeyServer.pubKey, "base64")); //derive the shared key
    console.log(sharedK);
    let message  = "from_deviceID:" + deviceID + "_w/:ECCDH_data:drive_pointbreak_inception";
    sendData(sessionID,sharedK,message); //shared key is ok --> send data (secret message)
}

// console.time("ECC");
// doECCDH(DEVICE_ID, 1)
// console.timeEnd("ECC")