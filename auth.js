var redis = require('redis');
var client = redis.createClient();
var uuid = require('node-uuid');
var btoa = require('btoa');
var atob = require('atob');
var hash = require('./hash');

exports.auth = function(settings) {
    if (settings.db !== 'redis') {
        console.log("isotope-auth requires redis for the moment");
        return function(){};
    }
    if (!settings.register
     || !settings.authredir) {
        console.log("incomplete settings");
        return function(){};
    }
    if (!settings.dbusers) {
        settings.dbusers = "auth:users";
    }
    if (!settings.authtimeout) {
        settings.authtimeout = 60*60*1000; // one hour
    }
    if (!settings.cookiename) {
        settings.cookiename = "auth";
    }
    return function(iso) {
        cookie = function(userUUID, resp) {
            uid = uuid.v4();
            client.hset(userUUID, "cookie", uid, function(e, s) {
                resp.writeHead(307, {
                    "Content-Type": "text/plain",
                    "Set-Cookie": settings.cookiename+"="+ btoa(JSON.stringify({
                        "cookie": uid,
                        "username": userUUID,
                        "time": (new Date).getTime() + settings.authtimeout
                    })) + ";path=/",
                    "Location":settings.authredir
                });
                resp.end();
            });
        }

        iso.auth = function(res, req, cb) {
            var authcookie = iso.cookies(req)[settings.cookiename];
            if (authcookie != null) {
                try {
                    var obj = JSON.parse(atob(authcookie));
                    if (obj === null) {
                        unauthorized(res);
                    } else {
                        client.hget(obj.username, "cookie", function(e, cookie) {
                            var ctime = (new Date).getTime();
                            if (cookie === obj.cookie && obj.time > ctime) {
                                cb(obj.username);
                            } else {
                                unauthorized(res);
                            }
                        });
                    }
                } catch (err) {
                    unauthorized(res);
                }
            } else {
                unauthorized(res);
            }
        }

        unauthorized = function(res) {
            setTimeout(function() {
                res.writeHead(401, { // could be 401, but I think this is better?
                    "Content-Type": "text/plain",
                });
                res.end("unauthorized");
            }, 2000);
        }

        iso.post(settings.register, function(res, req) {
            iso.extract_data(req, function(data) {
                client.hexists(settings.dbusers, data.username, function(err, status) {
                    if (status === 0) {
                        if (!(/^[a-zA-Z0-9]+$/.test(data.username))) {
                            res.writeHead(400, {"Content-Type":"text/plain"});
                            res.end("alphanumeric usernames only");
                        } else if (data.username.length > 20) {
                            res.writeHead(400, {"Content-Type":"text/plain"});
                            res.end("username maximum 20 characters");
                        } else if (data.password.length > 128) {
                            res.writeHead(400, {"Content-Type":"text/plain"});
                            res.end("pass maximum 128 characters");
                        } else {
                            var userUUID = uuid.v4();
                            var salt = uuid.v4();
                            var pwd = hash.hash(salt+data.password);
                            client.hset(settings.dbusers, data.username, userUUID, function(){});
                            client.hset(userUUID, 'password', pwd, function(){});
                            client.hset(userUUID, 'passalt', salt, function(){});
                            client.hset(userUUID, 'username', data.username, function(){});
                            cookie(userUUID, res);
                        }
                    } else {
                        res.writeHead(409, {"Content-Type":"text/plain"});
                        res.end("duplicate");
                    }
                });
            });
        });
        
        iso.post(settings.login, function(res, req) {
            iso.extract_data(req, function(data) {
                client.hexists(settings.dbusers, data.username, function(err, status) {
                    if (status === 0) {
                        setTimeout(function() {
                            res.writeHead(401, {"Content-Type":"text/plain"});
                            res.end("invalid username or password");
                        }, 2000);
                    } else {
                        client.hget(settings.dbusers, data.username, function(err, uuid) {
                            client.hget(uuid, 'password', function(err, pass) {
                                client.hget(uuid, 'passalt', function(err, salt) {
                                    var hpass = hash.hash(salt+data.password);
                                    if (hpass === pass) {
                                        cookie(uuid, res);
                                    } else {
                                        console.log(hpass);
                                        console.log(pass);
                                        setTimeout(function() {
                                            res.writeHead(401, {"Content-Type":"text/plain"});
                                            res.end("invalid username or password");
                                        }, 2000);
                                    }
                                });
                            });
                        });
                    }
                });
            });
        });
    }
}
