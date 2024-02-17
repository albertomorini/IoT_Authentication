//Alberto Morini - 4 Feb 2024 @ 00:31
const fs = require("fs");

/**
 * @param {int} length of the key
 * @returns {string} a key
 */
function genKey(length) { 
    let result = '';
    const characters = '123456789'; // remove the zero because we will convert into a number (avoid the start with zero)
    const charactersLength = characters.length;
    let counter = 0;
    while (counter < length) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
    }
    return result;
}
/**
 * @param {int} numberOfKeys 
 * @param {int} lenghtOfKey 
 * @returns {Array} the set of keys
 */
function createKeyset(numberOfKeys,lenghtOfKey){
    let keyset = []
    for (let i = 0; i < numberOfKeys; i++) {
        keyset.push(genKey(lenghtOfKey))
    }
    return keyset
}

let keyset = createKeyset(200,20);
console.log("Keyset of "+keyset.length+" elements:\n ["+ keyset + "]");

fs.writeFileSync("./secretVault.txt",'['+keyset.toString()+']'); //store into filesystem, thus to share with server and client