//Alberto Morini - 4 Feb 2024 @ 00:31
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

function createKeyset(numberOfKeys,lenghtOfKey){
    let keyset = []
    for (let i = 0; i < numberOfKeys; i++) {
        keyset.push(genKey(lenghtOfKey))
    }
    return keyset
}

let keyset = createKeyset(200,20);
console.log("Keyset of "+keyset.length+" elements : ["+ keyset + "]");

// [2744362711,1363714183,9265548211,2825833815,9364179924,9424779947,4192187843,7362916736]