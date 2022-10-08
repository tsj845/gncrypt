const { electron } = require("./common");
const { save, load, init, generatePair } = require("./lib");
// const { UnitConvo, GroupConvo, ConvoTop } = require("./_conversations");

// let __initpopupcallbackbuf = null;
// let __initpopupcallback = (...a) => __initpopupcallbackbuf = a;

// const login_cipher_key = new Promise((res, rej) => {
//     if (__initpopupcallbackbuf) {
//         res(__initpopupcallbackbuf[0]);
//     }
//     __initpopupcallback = (a) => {res(a);};
// });

// init(0, {intact:true,dms:{},grps:{}}, login_cipher_key);
// init(1, {}, login_cipher_key);

// const mykeys = load(1, login_cipher_key);
// let conversations = new ConvoTop(login_cipher_key);

const mykeys = generatePair();

async function main () {
    //
}

main();