const http = require("https");
const fs = require("fs");
const port = 1999;
const cyper = require ("./cypher.js");

const IOT_UIDS=["toyota","kia","mazda","jaguar"]; //UID of devices, will ignored potential message of unknown IoT device
const KEYS = [67713524793335768731, 26747432817864159792, 33761647468658116635, 93417431227443688669, 63125331514238389471, 26683246793273822124, 94653923953817875994, 29275399767855378451, 23641444157425921566, 57726129418776771567, 68792178625717166258, 26338843413942281637, 74937745895421198991, 22445648465164535287, 79569134286248244253, 14859681953857237515, 88715652531535229429, 62488235145442362484, 23171357938453614686, 25118343271271861765, 65293955717557159512, 93937467567783897429, 27179835434875614278, 66658626239822781718, 89863339227475756643, 15739456587776434458, 39927369384393946832, 76131912144735987798, 25525629613182819659, 72647927647393673432, 55585699489176951125, 22734888351528144767, 13123965956568642845, 16439849236475932768, 57995575354637967754, 56663565396681484699, 82866954454385871274, 81382565545564429691, 37862398247896694485, 69369787441231173467, 93127891984894436856, 38367611861144188914, 82666585552742959612, 66729855182639282134, 38295658466928411124, 94419389579874397587, 54586249641926651216, 46729682482192297129, 94951388484493994449, 58812368546954827315, 37747983472818756835, 73625135942421659271, 52999543827618989194, 15581565998947459164, 44182449562475249851, 64531395365674476326, 16384612565424345672, 34959461375786634324, 54247575151237888955, 42396849518899484393, 86587137465138923253, 98783112977323946521, 16947813615192365562, 31754794754458455991, 12494284687297491995, 99818171774523698752, 14645791337873323554, 31625252163946989663, 83441212862121827534, 14164467182391918356, 61556486554899283479, 58929792749198137369, 91359194697938253583, 23331684513988845152, 98431669136182639385, 69649461224311753273, 45845398916746498463, 85273717141712966826, 21363383257185272791, 84327468588598749334, 27613363864244155882, 52963392933792462213, 88833566544772411327, 56269616585363257623, 44496465598346176988, 86947372916669222392, 68531356858871984588, 25958351768685638613, 83836744789984852747, 34462641272459865435, 34222273689134921665, 74365782333445622746, 76723868929932228639, 83526226297621212989, 96635395913782191299, 25378635659328831398, 22393183358115353633, 92723297565393648825, 11769134424275971157, 49699516423126642337, 33443389428284411556, 83346592327332638876, 26331995984369586286, 45641737782178788586, 77799163325587641527, 79313877934336727977, 85214685452993669725, 47742229966484188555, 53223468197229373733, 36181795766845859478, 29418319459933699319, 44696773536515448862, 35987164794639672782, 66687263731781776158, 32973888423991794919, 14844349839395673246, 12991562484682933434, 63563261313629873318, 17951965764714747254, 48999225111646289124, 88383397566525628448, 81723363471445626482, 83872725193355996893, 17595863174523848771, 48386637147997876286, 68654354381495847332, 12416683384633448381, 99681239211176714311, 34957836243389817431, 24221911443794224523, 96258283653354966896, 57175131212877468422, 39391116334482471922, 45157663175188658245, 79536543937937152253, 57838458879124933912, 34838892295863829374, 51432164382518611513, 21183879149689833826, 55742196553663158397, 73228683852426211177, 26581191973416754151, 55732358516377771581, 23177776429519174365, 64542532195164934653, 83953263924599522923, 19721896655967611127, 75541663686389765652, 44399721384997196134, 24576452134811818956, 85459624348981539659, 73774316275883355135, 13494837984378345251, 39585533923644513971, 64819468715874336919, 83261719758963754224, 22354552517449758426, 87355238869769121777, 43664816811469571484, 97518687629354935431, 46757614589653762768, 69588678629665665884, 48355392716859788876, 95891563567862648564, 61378398282193579141, 17735746739271492937, 33837513364792897223, 75433977351222348398, 21764751167812382978, 31625846126357247849, 69259169286413346254, 22776966992597254624, 36815687566189162393, 95973678913422135614, 58459681879997793798, 73728168213353357178, 79141437279759155589, 99645582286518196715, 76165692144381765438, 98954476718129591787, 71988764894286214331, 78269389474283378754, 61265693927245665339, 75492484978355533657, 29232299849158121327, 53795518984955744949, 36328773637188111381, 67369989893264762413, 53412971666678685832, 93271386591963572184, 12342856826552281921, 64521421997728495415, 34376616816363945196, 29459344656951346824, 77174224116591438375, 18515578825592665368, 21495371379383362445, 69235152529665753964, 47387693684136415169, 26586956118654864819];

let sessionsID ={} //this set will used to store the generated keys for each session-client --> not specified in the paper, but server talks with several clients, so we can't use a unique variable to store the keys generated (k2,k3.. see on "third" step)


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

/**
 * TODO: explain that's is the first step of 3 way handshake
 * @param {Object} body the HTTP body request
 */
function firstStep(res,body){
    //check if the DeviceID is known 
    if (IOT_UIDS.includes(body.deviceID)) {
        let M2 = {};

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

    let C1 = sessionsID[body.sessionID + body.deviceID]; //retrieve C1 thus to have k1
    let k1 = ExecXOR(C1);
    console.log("k1:: " + k1);
    
    let tmpM3 = cyper.decrypt(body.alg,k1, body.M3);
    console.log(tmpM3);
    //TODO: ask if ok sentinel char ~~≥ JSON
    tmpM3 = JSON.parse(tmpM3);

    let k2 = ExecXOR(tmpM3.C2);


    let t2 = GetRandomInt();
    let M4 = cyper.encrypt(
        body.alg,
        k2 ^ tmpM3.t1,
        JSON.stringify({
            r2: tmpM3.r2,
            t2: t2
        })
    );
    console.log("Session t: " + (tmpM3.t1 ^ t2));
    sendResponse(res, 200, M4)

    sessionsID[body.sessionID + body.deviceID] = (tmpM3.t1 ^ t2)
}

/**
 * EXTRA PAPER: client will send a custom string, we will return the uppercase of that
 * @param {Object} body 
 */
function dataReceived(res,body){
    let sessionKey = sessionsID[body.sessionID + body.deviceID];
    let x = cyper.decrypt(body.alg,sessionKey, body.message);
    console.log(x);
}

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

        if(req.url=="/first"){  //first step of the handshake
            firstStep(res,body)
        }

        if(req.url=="/third"){ //third step of the handshake
            thirdStep(res,body);
        }


        if(req.url=="/data"){ //EXTRA PAPER: client send a string and we'll return the upper case of that
            dataReceived(res,body)
        }

    });

}).listen(port);
console.log("Server started at port: "+port);

