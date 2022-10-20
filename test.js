const { AddrBook } = require("./lib");

AddrBook.pack("stored.svrs", {"00000000":[false,"127.0.0.1",6000]});

console.log(AddrBook.unpack("stored.svrs"));