var express = require("express");
var parser = require("body-parser");

var app = express();
var registry = {};

app.use(parser.json());
app.get("/did/public_key", (req, res, next) => did_resolve(req, res, next));
app.post("/did/public_Key", (req, res, next) => did_create(req, res, next));

try {
    app.listen(3000, 'localhost', () => {
        console.log("Server running on 127.0.0.1:3000");
    }).on('error', ex => {
        if (ex.code == 'EADDRINUSE') {
            console.log('Server already running, semi-normal.');
            process.exit(1);
        } else {
            console.log(`Failed to start server: ${ex.message}`);
            process.exit(ex.code);
        }
    });    
} catch (ex) {
    console.log(`Server already running?\n ${ex}`);
    process.exit(1);
}

function did_resolve(req, res, next) {
    console.log(`Resolving did=${req.query?.did}`);

    if (!req.query || !req.query.did || !registry[req.query.did]) {
        console.log(`Responding 404 on did resolution of ${req.query?.did}`);
        res.sendStatus(404);
    } else {
        console.log(`Responding 200 on did resolution of ${req.query?.did} --> ${registry[req.query.did]}`);
        res.send(registry[req.query.did]);
    }
}

function did_create(req, res, next) {
    console.log(`Storing ${req.body?.did} -> ${req.body?.pubkey}`);
    if (!req.body || !req.body.did || !req.body.pubkey) {
        sendStatus(400);
    } else {
        registry[req.body.did] = req.body.pubkey;
        res.sendStatus(201);
    }
}
