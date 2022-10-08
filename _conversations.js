const { load, save } = require("./lib");

/**
 * @typedef Msg
 * @type {{sender:number,text:string}}
 */

/**
 * @typedef DMConvoD
 * @type {{other:number,log:Msg[]}}
 */

/**
 * @typedef GrpConvoD
 * @type {{others:number[],log:Msg[]}}
 */

/**
 * @typedef ConvoDescriptor
 * @type {{intact:boolean,dms:DMConvoD[],grps:GrpConvoD[]}}
 */

class UnitConvo {
    constructor (data) {}
    append (data) {}
}

class GroupConvo {
    constructor (data) {}
}

class ConvoTop {
    /**
     * @param {String|Buffer} key cipher key
     */
    constructor (key) {
        /**@type {ConvoDescriptor} */
        const data = load(false, key);
        if (data.intact !== true) {
            throw "Invalid Key";
        }
        /**@type {UnitConvo[]} */
        this.dms = [];
        /**@type {GroupConvo[]} */
        this.grps = [];
        for (const d of data.dms) {
            this.dms.push(new UnitConvo(d));
        }
    }
}

exports.ConvoTop = ConvoTop;
exports.UnitConvo = UnitConvo;
exports.GroupConvo = GroupConvo;