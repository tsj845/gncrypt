const { app, BrowserWindow, ipcMain } = require("electron");

let mwin;

function createWindow (p) {
    const win = new BrowserWindow({
        webPreferences: {nodeIntegration:true, contextIsolation: false},
    });
    win.loadFile(p);
    return win;
}

app.whenReady().then(() => {
    mwin = createWindow("index.html");
    mwin.on("close", () => {app.quit();});
    ipcMain.on("db:log", (_, a) => console.log(...JSON.parse(a)));
});