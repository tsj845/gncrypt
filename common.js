const { ipcRenderer } = require("electron");

const electron = {
    log (...args) {
        ipcRenderer.send("db:log", JSON.stringify(args));
    }
};

exports.electron = electron;