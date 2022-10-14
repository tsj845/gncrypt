const { NSocket, bytesToBig, bigToBytes, bufferToString, stringToBuffer } = require("./lib");
const net = require("net");

const server = net.createServer(async (ISOCKET) => {
    let socket = NSocket.from(ISOCKET);
    const name = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`CONNECTION FROM: ${name}`);
    await socket.write(0x01);
    console.log("STARTED");
    await socket.read(1);
    // await new Promise((r,_)=>{
    //     socket.once("close", ()=>{r();});
    // });
    while (true) {
        const d = await socket.read(1, {"format":"number","default":0xff});
        console.log(d);
        if (d === 0xff) {
            break;
        }
    }
    console.log("ended");
    // while (true) {
    //     let opcode = await socket.read(1, {"format":"number","default":0xff});
    //     if (opcode === 0xff) {
    //         console.log("ENDED");
    //         return;
    //     }
    //     console.log(`READING DATA FROM ${name}: ${bufferToString(await socket.read(bytesToBig([opcode, ...await socket.read(3)])), "utf-8")}`);
    // }
});
server.listen(4000, "0.0.0.0");