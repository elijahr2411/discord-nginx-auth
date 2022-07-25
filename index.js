// Discord Nginx Auth
// By Elijah R
// Copyright 2022
// Licensed under the GNU General Public License, latest version made available by the FSF

// Imports
const mysql = require("mysql");
const fs = require("fs");
const http = require("http");
const url = require("url");
const axios = require('axios');
const querystring = require('querystring');

// Import the config file
if (!fs.existsSync("config.json")) {
    console.error("config.json not found. Please make sure you've copied config.example.json and filled out all fields.");
    process.exit(1);
}
var config;
try {
    config = JSON.parse(fs.readFileSync("config.json"))
} catch {
    console.error("Failed to parse config.json. Please make sure it contains valid JSON data.");
    process.exit(1);
}
// Create the mysql connection
const db = mysql.createConnection({
    host: config.mysqlHost,
    user: config.mysqlUsername,
    password: config.mysqlPass,
    database: config.mysqlDb
});

// Init the database
async function dbConnect() {
    return new Promise((resolve, reject) => {
        db.connect((err) => {
            if (err) {reject(err);} else {
                console.log("Connected to the database");
                resolve();
            }
        })
    });
}

async function initDb() {
    return new Promise(async (res, rej) => {
        await dbConnect();
        db.query(`CREATE TABLE IF NOT EXISTS ${config.mysqlTablePrefix}ips (username TEXT, ip TEXT)`, (err, result) => {
            if (err) {
                rej(err);
            } else {
                res(result);
            }
        });
    });
}

// Check for a row
async function isIpInDb(ip) {
    return new Promise((res, rej) => {
        db.query(`SELECT ip FROM ${config.mysqlTablePrefix}ips WHERE ip=${db.escape(ip)}`, (err, result, fields) => {
            if (err) {
                rej(err);
            } else {
                if (result.length == 0) {
                    res(false);
                } else {
                    res(true);
                }
            }
        });
    });
}

// Insert row into database
async function whitelistIp(username, ip) {
    return new Promise((res, rej) => {
        db.query(`INSERT INTO ${config.mysqlTablePrefix}ips (username, ip) VALUES (${db.escape(username)}, ${db.escape(ip)})`, (err, result) => {
            if (err) {
                rej(err);
            } else {
                res(result);
            }
        });
    });
}

// Function to query discord api
var discord = {
    authorize: async (usertoken, ip) => {
        return new Promise (async (res, rej) => {
            var token;
            try {
                token = await discord.getToken(usertoken);
            } catch (err) {
                res(["INVALID_TOKEN"]);
                return;
            }
            var servers;
            try { servers = await discord.guildList(token.access_token);} catch {
                res("INTERNAL_ERROR");
                return;
            }
            var ids = [];
            for (var i = 0; i < Object.keys(servers).length; i++) {
                ids.push(servers[i].id);
            }
            if (!ids.includes(config.allowedGuild)) {
                res(["NOT_IN_GUILD"]);
                return;
            }
            var roles;
            try {roles = await discord.roleList(token.access_token);} catch {
                res("INTERNAL_ERROR");
                return;
            }
            var hasRequiredRole = false;
            roles.roles.forEach((curr) => {
                if (config.allowedRoles.includes(curr)) {
                    hasRequiredRole = true;
                }
            });
            if (hasRequiredRole) {
                var userdata;
                try {
                    userdata = await discord.getUser(token.access_token);
                } catch {
                    res("INTERNAL_ERROR");
                    return;
                }
                if (await isIpInDb(ip)) {
                    res(["ALREADY_AUTHORIZED"]);
                } else {
                    whitelistIp(userdata.username, ip);
                    res(["AUTHORIZED", userdata.username]);
                }
            } else {
                res(["NO_ROLE"]);
            }
        });
    },
    getToken: async (usertoken) => {
        return new Promise((res, rej) => {
            const data = `client_id=${config.discordClientId}&client_secret=${config.discordClientSecret}&grant_type=authorization_code&code=${usertoken}&redirect_uri=${config.canonicalUrl}${config.baseurl}/`;
            axios.post("https://discord.com/api/v10/oauth2/token", data, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }}).then((result) => {
                res(result.data);
            }).catch((err) => {
                rej(false);
            });
        });
    },
    guildList: async (usertoken) => {
        return new Promise((res, rej) => {
            axios.get(`https://discord.com/api/v10/users/@me/guilds`, {
                headers: {
                    'authorization': `Bearer ${usertoken}`
                }
            }).then((result) => {
                res(result.data);
            });
        });
    },
    roleList: async (usertoken) => {
        return new Promise((res, rej) => {
            axios.get(`https://discord.com/api/v10/users/@me/guilds/${config.allowedGuild}/member`, {
                headers: {
                    'authorization': `Bearer ${usertoken}`
                }
            }).then((result => {
                res(result.data);
            })).catch((err) => {
                rej(err);
            });
        });
    },
    getUser: async (usertoken) => {
        return new Promise((res, rej) => {
            axios.get(`https://discord.com/api/v10/users/@me`, {
                headers: {
                    'authorization': `Bearer ${usertoken}`
                }
            }).then((result => {
                res(result.data);
            })).catch((err) => {
                rej(err);
            });
        });
    }
}


// Create HTTP Server
const server = http.createServer(async (req, res) => {
    var requrl = url.parse(req.url, true);
    var ip;
    if (Array.isArray(req.headers["x-forwarded-for"])) {
        ip = req.headers["x-forwarded-for"][0];
    } else if (req.headers["x-forwarded-for"].includes(", ")) {
        ip = req.headers["x-forwarded-for"].split(", ")[0];
    } else {
        ip = req.headers["x-forwarded-for"]
    }
    switch(requrl.pathname) {
        case `${config.baseurl}/`:
            if (requrl.query.code == undefined) {
                res.writeHead(302, {
                    Location: `https://discord.com/api/oauth2/authorize?client_id=${encodeURIComponent(config.discordClientId)}&redirect_uri=${encodeURIComponent(`${config.canonicalUrl}${config.baseurl}/`)}&response_type=code&scope=identify%20guilds%20guilds.members.read`
                });
                res.end();
            } else {
                var token = await discord.authorize(requrl.query.code, ip);
                switch (token[0]) {
                    case "INVALID_TOKEN":
                        res.writeHead(400);
                        res.end("400: Invalid Token");
                        break;
                    case "NOT_IN_GUILD":
                        res.writeHead(403);
                        res.end("403: You are not in the required guild");
                        break;
                    case "NO_ROLE":
                        res.writeHead(403);
                        res.end("403: You do not have the required role.");
                        break;
                    case "ALREADY_AUTHORIZED":
                        res.writeHead(200);
                        res.end("This ip is already authorized.");
                        break;
                    case "AUTHORIZED":
                        res.writeHead(200);
                        res.end(`Successfully authorized ${token[1]} at ${ip}`);
                        console.log(`Authorized ${token[1]} to ${ip}`);
                        break;
                    default:
                        res.writeHead(500);
                        res.end("500: Internal Server Error.");
                        break;
                }
            }
            break;
        case `${config.baseurl}/authrequest`:
            if (await isIpInDb(ip)) {
                res.writeHead(200);
            } else {
                res.writeHead(403);
            }
            res.end();
            break;
        default:
            res.writeHead(404);
            res.end("404");
            break;
    }
});


// All the async shit goes in here
async function main() {
    // Connect to the database
    await initDb();
    console.log(`Starting webserver on port ${config.listenPort}`);
    server.listen(config.listenPort);
}
main();
