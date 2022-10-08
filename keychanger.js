const { save } = require("./lib");
const { readFileSync } = require("fs");

const data = readFileSync(__dirname + "/stored.keys").toString().split(/(?<=\n)\n\n/);
save(true, {pub:data[0],pri:data[1]}, process.argv[0]);