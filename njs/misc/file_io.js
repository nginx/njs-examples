var fs = require('fs');
var STORAGE = "/tmp/njs_storage"

function push(r) {
    fs.appendFileSync(STORAGE, r.requestText);
    r.return(200);
}

function flush(r) {
    fs.writeFileSync(STORAGE, "");
    r.return(200);
}

function read(r) {
    var data = "";
    try {
        data = fs.readFileSync(STORAGE);
    } catch (e) {
    }

    r.return(200, data);
}

export default {push, flush, read};
