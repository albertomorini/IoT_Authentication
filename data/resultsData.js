
/*
secondStep: 1.095ms
fourthStep: 0.158ms
Session t: 224


secondStep: 0.414ms
fourthStep: 0.034ms
Session t: 101


secondStep: 0.301ms
fourthStep: 0.033ms
Session t: 249


secondStep: 0.239ms
fourthStep: 0.035ms
Session t: 24


secondStep: 0.244ms
fourthStep: 0.034ms
Session t: 126


secondStep: 0.312ms
fourthStep: 0.026ms
Session t: 4


secondStep: 0.268ms
fourthStep: 0.024ms
Session t: 91


secondStep: 0.236ms
fourthStep: 0.021ms
Session t: 238


secondStep: 0.24ms
fourthStep: 0.085ms
Session t: 60


secondStep: 0.249ms
fourthStep: 0.028ms
Session t: 10


 */


let paper128=[
1.095,
0.158,
0.414,
0.034,
0.301,
0.033,
0.239,
0.035,
0.244,
0.034,
0.312,
0.026,
0.268,
0.024,
0.236,
0.021,
0.24,
0.085,
0.249,
0.028


]


console.log("Average paper AES128:" + paper128.reduce((a, b) => (0, a + b)) / 10); //we executed 10 times

/*

Test 10 time the algorithm of the paper

secondStep: 1.087ms
fourthStep: 0.145ms
                Session t: 211

secondStep: 0.429ms
fourthStep: 0.035ms
                Session t: 92

secondStep: 0.298ms
fourthStep: 0.035ms
                Session t: 57

secondStep: 0.241ms
fourthStep: 0.035ms
                Session t: 152


secondStep: 0.264ms
fourthStep: 0.027ms
                Session t: 126


secondStep: 0.284ms
fourthStep: 0.024ms
                Session t: 52


secondStep: 0.23ms
fourthStep: 0.024ms
                Session t: 10


secondStep: 0.226ms
fourthStep: 0.022ms
                Session t: 166


secondStep: 0.211ms
fourthStep: 0.08ms
                Session t: 66


secondStep: 0.244ms
fourthStep: 0.04ms
                Session t: 131

*/


let paper256= [1.087
,0.145
,0.429
,0.035
,0.298
,0.035
,0.241
,0.035
,0.264
,0.027
,0.284
,0.024
,0.23
,0.024
,0.226
,0.022
,0.211
,0.08
,0.244
,0.04]

console.log("Average paper AES256:" +paper256.reduce((a,b)=>(0,a+b))/10); //we executed 10 times






/*

let's test 10 time the ECC_DH key exchange
ECC_KeyExc: 31.22ms

ECC_KeyExc: 22.348ms

ECC_KeyExc: 10.463ms

ECC_KeyExc: 3.652ms

ECC_KeyExc: 3.019ms

ECC_KeyExc: 3.422ms

ECC_KeyExc: 2.94ms

ECC_KeyExc: 2.852ms

ECC_KeyExc: 2.851ms

ECC_KeyExc: 2.797ms


 */


let resultECC = [
31.22,
22.348,
10.463,
3.652,
3.019,
3.422,
2.94,
2.852,
2.851,
2.797
]

console.log("Average ECCDH with outliers:" + resultECC.reduce((a, b) => (0, a + b)) / 10); //we executed 10 times
let resultECC_woutOutliers = [
    3.652,
    3.019,
    3.422,
    2.94,
    2.852,
    2.851,
    2.797
]


console.log("Average ECCDH without outliers:" + resultECC_woutOutliers.reduce((a, b) => (0, a + b)) / 7); //we executed 10 times
