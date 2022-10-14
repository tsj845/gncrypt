const { electron } = require("./common");
const { save, load, init, generatePair, NSocket, OSocket, bytesToBig, bigToBytes, stringToBuffer, bufferToString, formatBuf } = require("./lib");
const net = require("net");

// defs
/**@type {HTMLDivElement} */
const connect_panel = document.getElementById("connect-panel");
/**@type {HTMLInputElement} */
const addr_inp = document.getElementById("ip-entry");
/**@type {HTMLInputElement} */
const connect_btn = document.getElementById("connect-btn");
/**@type {HTMLSpanElement} */
const con_fail = document.getElementById("con-fail");
/**@type {HTMLDivElement} */
const pend_cons = document.getElementById("pending-cons");
/**@type {HTMLImageElement} */
const con_wait = document.getElementById("con-wait");
/**@type {HTMLInputElement} */
const exit_chat = document.getElementById("exit-chat");
/**@type {HTMLDivElement} */
const convo = document.getElementById("convo");

addr_inp.value = "127.0.0.1:4000";

const mykeys = generatePair();

/**
 * @param {*} name
 * @returns {HTMLDivElement}
 */
function createPendingConnection (name) {
    const d = document.createElement("div");
    d.append(name);
    const a = document.createElement("input");
    a.type = "button";
    a.value = "Y";
    const b = document.createElement("input");
    b.type = "button";
    b.value = "N";
    d.appendChild(a);
    d.appendChild(b);
    d.className = "pend-con";
    pend_cons.appendChild(d);
    return d;
}

function addMsg (msg) {
    const d = document.createElement("div");
    d.textContent = msg;
    convo.appendChild(d);
}

/**@type {NSocket} */
let cser = null;

// let connect_server = net.createServer(/**@param {NSocket} sock */async (sock) => {
//     sock = NSocket.from(sock);
//     cser = sock;
//     const name = `${sock.remoteAddress}:${sock.remotePort}`;
//     const c = createPendingConnection(name);
//     let s = await new Promise((r,_)=>{
//         c.children[0].addEventListener("click", ()=>{r(1);});
//         c.children[1].addEventListener("click", ()=>{r(0);});
//     });
//     pend_cons.removeChild(c);
//     console.log(s);
//     if (!s) {
//         await sock.write(0x00);
//         console.log("REJ FIN");
//         sock.end();
//         return;
//     }
//     console.log("NOT ENDED");
//     await sock.write(0x01);
//     console.log("x2");
//     let x = await new Promise((r,_)=>{
//         exit_chat.addEventListener("click", ()=>{console.log("x");r(false);});
//         // async function repcall() {
//         //     if (sock.readableLength) {
//         //         if (await sock.read(1, {"format":"number"}) === 0xff) {
//         //             r(true);
//         //             return;
//         //         }
//         //         let data = await sock.read(bytesToBig(await sock.read(4)),{"encoding":"utf-8","format":"string"});
//         //         addMsg(data);
//         //     }
//         //     setTimeout(repcall, 250);
//         // }
//         // repcall();
//     });
//     console.log(x);
//     if (x) return;
//     await sock.write(0xff);
//     sock.end();
// });
// connect_server.listen(4000, "0.0.0.0");

let buff;
let sendout = false;

function senddat (str) {
    const b = stringToBuffer(str, false);
    const len = bigToBytes(b.length, 4);
    console.log("len", len);
    buff = Buffer.concat([Buffer.from(len), b]);
    sendout = true;
}

senddat("string");

console.log(formatBuf(buff));

/**@type {NSocket} */
let csock = null;

let endcon = false;

init(true, {"00000000":["127.0.0.1",6000]}, "pass");

let storages = load(true, "pass");

console.log(storages);

/**
 * gets ip addresses from storage servers
 * @param {[Buffer][]} client_ids client ids
 * @returns {IpAddr[]}
 */
function grap_ips (client_ids) {
    let f = [];
    return f;
}

connect_btn.addEventListener("click", async () => {
    if (csock) {
        csock.end();
    }
    con_fail.hidden = true;
    con_wait.hidden = false;
    let sock = new NSocket();
    csock = sock;
    const s = await new Promise((r,_)=>{sock.connect(Number(addr_inp.value.split(":")[1]), addr_inp.value.split(":")[0]);sock.once("error",()=>{r(0)});sock.once("connect",()=>{r(1)});});
    con_wait.hidden = true;
    if (!s) {
        con_fail.hidden = false;
        return;
    }
    let r = await sock.read(1, {"format":"number"});
    if (!r) {
        con_fail.hidden = false;
    }
    sock.on("end", () => {console.log("ENDED")});
    async function mainLoop () {
        if (sendout) {
            sendout = false;
            await sock.write(buff);
        }
        if (endcon) {
            endcon = false;
            return sock.end();
        } else {
            setTimeout(()=>{mainLoop();}, 0);
        }
    }
    mainLoop();
});

async function main () {
    //
}

main();