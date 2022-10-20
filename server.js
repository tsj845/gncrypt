const { NSocket, bytesToBig, bigToBytes, bufferToString, stringToBuffer } = require("./lib");
const net = require("net");

class Server {
    constructor () {
        this.data;
    }
    /**
     * socket connection
     * @param {net.Socket} sock
     */
    async connect (sock) {
        let socket = NSocket.from(sock);
        while (true) {}
    }
}