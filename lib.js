const { generateKeyPairSync, publicEncrypt, privateDecrypt, KeyObject, createPublicKey, createPrivateKey, createHash } = require("crypto");
const { readFileSync, writeFileSync, existsSync } = require("fs");
const join_path = require("path").join;
const { Socket } = require("net");

const msgpath = join_path(__dirname, "stored.msgs");
const keypath = join_path(__dirname, "stored.keys");

/**
 * encrypts a message using a key
 * @param {KeyObject} key
 * @param {String} msg
 * @returns {Buffer}
 */
function encrypt (key, msg) {
    return publicEncrypt(key, Buffer.from(msg));
}

/**
 * decrypts a message using a key
 * @param {KeyObject} key
 * @param {Buffer} msg
 * @returns {String}
 */
function decrypt (key, msg) {
    return privateDecrypt(key, msg).toString();
}

/**
 * @returns {publicKey:KeyObject,privateKey:KeyObject}
 */
function generatePair () {
    return generateKeyPairSync("rsa", {modulusLength:4096,publicKeyEncoding:{format:"pkcs1",type:"pem"},privateKeyEncoding:{format:"pkcs1",type:"pem"}});
}

/**
 * abs for BigInt
 * @param {BigInt} x
 * @returns {BigInt}
 */
function BIAbs (x) {
    return x < 0n ? -x : x;
}

/**
 * rolls a BigInt
 * @param {BigInt} big big number to roll
 * @param {BigInt} amt bits to roll
 * @returns {BigInt}
 */
function rol64 (big, amt) {
    return (big << amt) | (big >> (64n - amt));
}

class Random {
    /**
     * @param {Number|BigInt|BigUint64Array|String} [seed] optional seed
     */
    constructor (seed) {
        /**@private */
        this.state = new BigUint64Array(4);
        this.setState(seed);
    }
    /**
     * @returns {BigUint64Array}
     */
    getState () {
        return new BigUint64Array(this.state);
    }
    /**
     * sets the internal state
     * @param {Number|BigInt|BigUint64Array|String} state value to set the internal state to
     */
    setState (state) {
        if (typeof state === "object") {
            let inv = false;
            try {
                new BigUint64Array(state);
            } catch {
                inv = true;
            }
            if (inv || state.length === 0) {this.setState();return;}
            let i = 0;
            for (const item of state) {
                if (i >= 4) break;
                this.state[i] = state[i];
                i ++;
            }
            while (i < 4) {
                this.state[i] = 0n;
                i ++;
            }
            return;
        }
        if (typeof state === "string") {
            let hv = 0;
            for (const c of state) {
                hv += c.charCodeAt(0);
            }
            this.setState(hv);
            return;
        }
        let v = null;
        if (typeof state === "number" && state !== 0) {
            v = BigInt(Math.abs(state));
        } else if (typeof state === "bigint") {
            v = BIAbs(state);
        } else {
            v = BigInt(Math.floor(Math.random() * 1e20 + 1));
        }
        this.state = this.state.fill(v);
    }
    /**
     * steps the state
     * DO NOT USE THIS METHOD, for a raw value see {@link Random.raw}
     * @private
     * @returns {BigInt}
     */
    step () {
        const result = rol64(this.state[1] * 5n, 7n) * 9n;
        const t = this.state[1] << 17n;

        this.state[2] ^= this.state[0];
        this.state[3] ^= this.state[1];
        this.state[1] ^= this.state[2];
        this.state[0] ^= this.state[3];

        this.state[2] ^= t;
        this.state[3] = rol64(this.state[3], 45n);

        return result;
    }
    /**
     * returns raw value between 0 and Number.MAX_SAFE_INTEGER, use {@link Random.random} for a value matching the format of {@link Math.random}
     * @returns {Number}
     */
    raw () {
        return Number(BigInt.asUintN(54, this.step()));
    }
    /**
     * returns a number between 0 and 1
     * @returns {Number}
     */
    random () {
        return this.raw() / Number.MAX_SAFE_INTEGER;
    }
    /**
     * returns an integer between lo (inclusive) and hi (exclusive)
     * @param {Number} [lo] min
     * @param {Number} [hi] max
     * @returns {Number}
     */
    randint (lo, hi) {
        return Math.floor(this.random() * (hi ?? Number.MAX_SAFE_INTEGER - lo ?? 0) + lo ?? 0);
    }
    /**
     * returns a float between the specified lo and hi values
     * @param {Number} [lo] min
     * @param {Number} [hi] max
     * @returns {Number}
     */
    randf (lo, hi) {
        return this.random() * (hi ?? Number.MAX_SAFE_INTEGER - lo ?? 0) + lo ?? 0;
    }
    /**
     * shuffles a list and returns it for chaining
     * @template T
     * @param {T[]} arr list to shuffle
     * @returns {T[]}
     */
    shuffle (arr) {
        const n = arr.length;
        for (let i = 0; i < n - 1; i ++) {
            const change = this.randint(i, n - i);
            const held = arr[i];
            arr[i] = arr[change];
            arr[change] = held;
        }
        return arr;
    }
    /**
     * chooses a random element from a list and returns
     * @template T
     * @param {T[]} arr list to choose from
     * @returns {T}
     */
    choose (arr) {
        return arr[this.randint(0, arr.length)];
    }
    /**
     * generates a buffer of random bytes with length bytecount
     * @param {Number} bytecount number of bytes to generate
     * @returns {Buffer}
     */
    randbuf (bytecount) {
        let buf = Buffer.alloc(bytecount);
        for (let i = 0; i < bytecount; i ++) {
            buf[i] = this.randint(0, 256);
        }
        return buf;
    }
}

class Cryptor {
    /**
     * @param {String|Buffer} key
     * @param {Number} secl
     */
    constructor (key, secl) {
        /**@private */
        this.generator = new Random(key);
        /**@private */
        this._key = this.generator.randbuf(32);
        /**@private */
        this._keyidx = 0;
        /**@private */
        this._keylength = this._key.length;
        /**@private */
        this._secl = 1;
    }
    /**
     * transforms the given data
     * @param {Buffer} data
     * @returns {Buffer}
     */
    crypt (data) {
        let output = [];
        for (let i = 0; i < data.length; i ++) {
            // for (let j = 0; j < this._secl; j ++) {
                output.push(data[i] ^ this._key[this._keyidx]);
                this._keyidx ++;
                if (this._keyidx >= this._keylength) {
                    this._keyidx = 0;
                    this._key = this.generator.randbuf(32);
                }
            // }
        }
        return Buffer.from(output);
    }
}

/**
 * @typedef NBufferEncoding
 * @type {"utf-8"|"utf8"|"utf-16"|"utf16"|"ascii"}
 */

/**
 * provides helper methods on {@link Socket}
 * 
 * the methods ```NSocket``` overrides are: {@link NSocket.read}, {@link NSocket.write}, {@link NSocket.end}
 * 
 * ```NSocket``` also adds four new methods: {@link NSocket.bundle}, {@link NSocket.flush}, {@link NSocket.setCryptor}, {@link NSocket.setUseEncryption}
 * 
 * @example <caption>creating a new NSocket</caption>
 * const socket = new NSocket();
 * socket.connect(port, ip);
 * const numbers = await socket.read(4);
 * @example <caption>creating an NSocket from an existing Socket</caption>
 * socket = NSocket.from(socket);
 * const numbers = await socket.read(4);
 */
 class NSocket extends Socket {
    constructor () {
        super();
        this.pause();
        /**@private */
        this._oread = Socket.prototype.read;
        /**@private */
        this._owrite = Socket.prototype.write;
        /**@private */
        this._oend = Socket.prototype.end;
        /**@type {Cryptor} @private */
        this.cryptor = null;
        /**@private */
        this.ending = false;
        /**@private */
        this.use_cryptor = true;
        /**@private */
        this.do_flush = true;
        /**@type {Buffer[]} @private */
        this.bundled = [];
        /**@type {number} @public */
        this.refid = 0;
        const that = this;
        function rebind () {
            that.write = NSocket.prototype.write;
            that.read = NSocket.prototype.read;
            that.end = NSocket.prototype.end;
        }
        this.once("connect", rebind);
    }
    /**
     * converts a Socket to an NSocket
     * @param {Socket} socket {@link Socket} to convert
     * @returns {NSocket}
     */
    static from (socket) {
        socket.pause();
        socket._oread = Socket.prototype.read;
        socket._owrite = Socket.prototype.write;
        socket._oend = Socket.prototype.end;
        socket.read = NSocket.prototype.read;
        socket.write = NSocket.prototype.write;
        socket.end = NSocket.prototype.end;
        socket._wwrite = NSocket.prototype._wwrite;
        socket.do_flush = true;
        socket.cryptor = null;
        socket.use_cryptor = true;
        socket.ending = false;
        socket.setCryptor = NSocket.prototype.setCryptor;
        socket.setUseEncryption = NSocket.prototype.setUseEncryption;
        socket.bundled = [];
        socket.bundle = NSocket.prototype.bundle;
        socket.flush = NSocket.prototype.flush;
        return socket;
    }
    /**
     * bundles the {@link NSocket.write} commands until {@link NSocket.flush} is called
     * 
     * use this to bundle any write commands that can be sent together to reduce network load
     */
    bundle () {
        this.do_flush = false;
    }
    /**
     * flushes the bundled {@link NSocket.write} commands
     */
    flush () {
        this.do_flush = true;
        if (this.bundled.length === 0) return true;
        this._owrite(Buffer.concat(this.bundled));
        this.bundled = [];
        return false;
    }
    /**
     * sets the internal cryptor
     * @param {Cryptor} cryptor the cryptor to set, see {@link SymmetricCipher} for info on what this does
     */
    setCryptor (cryptor) {
        this.cryptor = cryptor;
    }
    /**
     * sets whether the {@link NSocket} is using encryption, see {@link NSocket.setCryptor} for info on the cryptor
     * @param {boolean} use whether to use encryption
     */
    setUseEncryption (use) {
        this.use_cryptor = use;
    }
    /**
     * overrides the end method to ensure that all data is finished being written before ending the connection
     * @override
     * @param {()=>void} cb
     */
    end (cb) {
        cb = cb || (() => {});
        this.ending = true;
        let x = true;
        if (!this.do_flush) {
            x = this.flush();
        }
        if (this.writableFinished && x) {
            return this._oend(cb);
        }
        this.once("drain", () => {this._oend(cb)});
        this.emit("cClose");
    }
    /**
     * @param {Buffer} data
     */
    _wwrite (data) {
        if (typeof data === "string" && !this.do_flush) return this.bundled.push(stringToBuffer(data, true));
        if (!this.do_flush) return this.bundled.push(data);
        this._owrite(data);
    }
    /**
     * writes data to the socket``
     * 
     * note that when the internal cryptor is set the ```strIsUtf8``` parameter becomes applicable
     * @param {string | number | Buffer | number[]} data data to write
     * @param {boolean} [strIsUtf8] passed through to the internal cryptor if applicable see {@link SymmetricCipher.crypt} for more info
     * @returns {Promise<void>}
     */
    write (data, strIsUtf8) {
        const that = this;
        return new Promise((res, _) => {
            if (that.ending) return res();
            if (that.cryptor !== null && that.cryptor !== undefined && that.use_cryptor) {
                data = that.cryptor.crypt(data, strIsUtf8);
            }
            if (typeof data === "string") {
                that._wwrite(data);
            } else if (typeof data === "number") {
                that._wwrite(Uint8Array.of(data & 0xff));
            } else {
                that._wwrite(Uint8Array.from(data));
            }
            if (this.do_flush) {
                that.once("drain", res);
            } else {
                res();
            }
        });
    }
    /**
     * @typedef readOptions
     * @type {object}
     * @property {number|number[]|Buffer} [default] default value to return if connection fails
     * @property {"number"|"array"|"buffer"|"string"} [format] format to return data in, if ```"string"``` is used {@link readOptions.encoding} must be provided as well
     * @property {NBufferEncoding} [encoding] the encoding to use when ```format``` is ```"string"```, defaults to ```"utf-16"```
     */
    /**
     * async operation to read from the socket
     * @param {number} size size, in bytes, to read
     * @param {readOptions} [options] options for reading
     * @returns {Promise<number[]>}
     */
    read (size, options) {
        // const evE = new Error();
        /**@type {Buffer} */
        let buf = null;
        if (options?.default !== null && options?.default !== undefined) {
            options.default = typeof options.default === "number" ? Buffer.alloc(1, options.default) : Array.isArray(options.default) ? Buffer.from(options.default) : options.default;
        }
        const that = this;
        let defaulted = false;
        function toCall (r) {
            // try {
            buf = that._oread(size);
            // } catch (e) {e.stack += evE.stack; throw e;}
            if (that.readableEnded) {
                defaulted = true;
                buf = options?.default ?? Buffer.of(0x00);
            }
            if (buf !== null) {
                if (that.cryptor !== null && that.cryptor !== undefined && that.use_cryptor && !defaulted) {
                    buf = that.cryptor.crypt(buf, !["utf-16", "utf16"].includes((options?.encoding ?? "utf-8")));
                }
                switch (options?.format) {
                    case "number":
                        if (buf.length === 1) {
                            r(buf[0]);
                            break;
                        } else {
                            r(Array.from(buf));
                            break;
                        }
                    case "buffer":
                        r(buf);
                        break;
                    case "string":
                        if (["utf8", "uft-8"].includes(options?.encoding)) {
                            r(buf.toString("utf-8"));
                        } else if (options.encoding === "ascii") {
                            r(buf.toString("ascii"));
                        } else {
                            r(bufferToString(buf));
                        }
                        break;
                    default:
                        r(Array.from(buf));
                        break;
                }
                return;
            }
            setTimeout(()=>{toCall(r)}, 0);
        }
        return new Promise((res, _) => {
            toCall(res);
        });
    }
}

/**
 * converts a string to a buffer of the bytes that the string is made from
 * @param {string | Buffer} str string to convert
 * @param {boolean} [asascii] whether to return in ASCII
 * @param {number} [padto] length to pad to, default no padding
 * @param {number} [padwith] what to pad the buffer with
 * @returns {Buffer}
 */
 function stringToBuffer (str, asascii, padto, padwith) {
    if (Buffer.isBuffer(str)) return str;
    let f = [];
    for (let i = 0; i < str.length; i ++) {
        const x = str.charCodeAt(i);
        if (!asascii) {
            f.push((x & 0xff00) >> 8);
        }
        else if (f > 127) {
            continue;
        }
        f.push(x & 0xff);
    }
    if (padto ?? false) {while (f.length < padto) {f.push(padwith);}}
    // console.log(f.length, "FLEN");
    return Buffer.from(f);
}

/**
 * converts a buffer to text
 * @param {Buffer|number[]} buf buffer to convert
 * @param {NBufferEncoding} [encoding] text encoding defaults to ```utf-16```
 */
function bufferToString (buf, encoding) {
    encoding = encoding || "utf-16";
    if (!["utf16", "utf-16"].includes(encoding)) {
        return (Array.isArray(buf) ? Buffer.from(buf) : buf).toString(encoding);
    }
    if (buf.length % 2) {
        throw new InvalidDataError(`utf-16 requires even number of bytes but got "${buf.length}" instead`);
    }
    let f = "";
    for (let i = 0; i < buf.length; i += 2) {
        f += String.fromCharCode((buf[i] << 8) | buf[i+1]);
    }
    return f;
}

/**
 * saves the given object
 * @param {Boolean} l when true use msgs else use keys
 * @param {Object} obj object to save
 * @param {String|Buffer} key cipher key
 */
function save (l, obj, key, sl) {
    let c = new Cryptor(key, sl);
    writeFileSync(l ? msgpath : keypath, c.crypt(Buffer.from(JSON.stringify(obj))));
}

/**
 * loads an object
 * @param {Boolean} l when true use msgs else use keys
 * @param {String|Buffer} key cipher key
 * @returns {Object}
 */
function load (l, key, sl) {
    let c = new Cryptor(key, sl);
    return JSON.parse(c.crypt(readFileSync(l ? msgpath : keypath)).toString());
}

function init (l, obj, key) {
    const p = l ? msgpath : keypath;
    if (existsSync(p)) {
        return;
    }
    save(l, obj, key);
}

exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.generatePair = generatePair;
exports.store_crypt = store_crypt;
exports.save = save;
exports.load = load;
exports.init = init;
exports.Cryptor = Cryptor;
exports.Random = Random;