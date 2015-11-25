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
    if (!settings.landingpage
     || !settings.landing
     || !settings.register
     || !settings.authredir
     || !settings.login) {
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
                resp.writeHead(307, { // could be 401, but I think this is better?
                    "Content-Type": "text/plain",
                    "Location":settings.authredir
                });
                res.end("unauthorized");
            }, 2000);
        }

        iso.get("hash.js", function(res, req) {
            res.writeHead(200, {"Content-Type":"text/javascript"});
            sendjs(res);
        });

        iso.get(settings.landing, function(res, req) {
            var salt = uuid.v4();
            var saltkey = uuid.v4();
            var time = (new Date).getTime();

            client.set(saltkey, salt, function(err, status) {
                client.expire(saltkey, 10*60, function() {
                    iso.template(res, settings.landingpage, {
                        "salt" : salt,
                        "saltk" : saltkey
                    });
                });
            });
        });

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
                        }
                        var userUUID = uuid.v4();
                        client.hset(settings.dbusers, data.username, userUUID, function(){});
                        client.hset(userUUID, 'password', data.password, function(){});
                        client.hset(userUUID, 'username', data.username, function(){});
                        cookie(userUUID, res);
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
                        client.get(data.saltkey, function(err, salt) {
                            if (err) {
                                res.writeHead(401, {"Content-Type":"text/plain"});
                                res.end("Maximum login time exceded");
                            } else {
                                client.hget(settings.dbusers, data.username, function(err, uuid) {
                                    client.hget(uuid, 'password', function(err, pwd) {
                                        pwd = salt + pwd;
                                        comp = hash.hash(pwd);
                                        if (comp === data.password) {
                                            cookie(uuid, res);
                                        } else {
                                            setTimeout(function() {
                                                res.writeHead(401, {"Content-Type":"text/plain"});
                                                res.end("invalid username or password");
                                            }, 2000);
                                        }
                                    });
                                });
                            }
                        });
                    }
                });
            });
        });
    }
}


sendjs = function(res) {
    res.write("function hex_sha512(n){return rstr2hex(rstr_sha512(str2rstr_utf8(n)))}");
    res.write("function b64_sha512(n){return rstr2b64(rstr_sha512(str2rstr_utf8(n)))}");
    res.write("function any_sha512(n,t){return rstr2any(rstr_sha512(str2rstr_utf8(n))");
    res.write(",t)}function hex_hmac_sha512(n,t){return rstr2hex(rstr_hmac_sha512(str");
    res.write("2rstr_utf8(n),str2rstr_utf8(t)))}function b64_hmac_sha512(n,t){return ");
    res.write("rstr2b64(rstr_hmac_sha512(str2rstr_utf8(n),str2rstr_utf8(t)))}function");
    res.write(" any_hmac_sha512(n,t,r){return rstr2any(rstr_hmac_sha512(str2rstr_utf8");
    res.write("(n),str2rstr_utf8(t)),r)}function sha512_vm_test(){return'ddaf35a19361");
    res.write("7abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836");
    res.write("ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'==hex_sha512('abc').toL");
    res.write("owerCase()}function rstr_sha512(n){return binb2rstr(binb_sha512(rstr2b");
    res.write("inb(n),8*n.length))}function rstr_hmac_sha512(n,t){var r=rstr2binb(n);");
    res.write("r.length>32&&(r=binb_sha512(r,8*n.length));for(var e=Array(32),i=Array");
    res.write("(32),h=0;32>h;h++)e[h]=909522486^r[h],i[h]=1549556828^r[h];var a=binb_");
    res.write("sha512(e.concat(rstr2binb(t)),1024+8*t.length);return binb2rstr(binb_s");
    res.write("ha512(i.concat(a),1536))}function rstr2hex(n){try{}catch(t){hexcase=0}");
    res.write("for(var r,e=hexcase?'0123456789ABCDEF':'0123456789abcdef',i='',h=0;h<n");
    res.write(".length;h++)r=n.charCodeAt(h),i+=e.charAt(r>>>4&15)+e.charAt(15&r);ret");
    res.write("urn i}function rstr2b64(n){try{}catch(t){b64pad=''}for(var r='ABCDEFGH");
    res.write("IJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',e='',i=n.len");
    res.write("gth,h=0;i>h;h+=3)for(var a=n.charCodeAt(h)<<16|(i>h+1?n.charCodeAt(h+1");
    res.write(")<<8:0)|(i>h+2?n.charCodeAt(h+2):0),o=0;4>o;o++)e+=8*h+6*o>8*n.length?");
    res.write("b64pad:r.charAt(a>>>6*(3-o)&63);return e}function rstr2any(n,t){var r,");
    res.write("e,i,h,a,o=t.length,w=Array(Math.ceil(n.length/2));for(r=0;r<w.length;r");
    res.write("++)w[r]=n.charCodeAt(2*r)<<8|n.charCodeAt(2*r+1);var l=Math.ceil(8*n.l");
    res.write("ength/(Math.log(t.length)/Math.log(2))),c=Array(l);for(e=0;l>e;e++){fo");
    res.write("r(a=Array(),h=0,r=0;r<w.length;r++)h=(h<<16)+w[r],i=Math.floor(h/o),h-");
    res.write("=i*o,(a.length>0||i>0)&&(a[a.length]=i);c[e]=h,w=a}var s='';for(r=c.le");
    res.write("ngth-1;r>=0;r--)s+=t.charAt(c[r]);return s}function str2rstr_utf8(n){f");
    res.write("or(var t,r,e='',i=-1;++i<n.length;)t=n.charCodeAt(i),r=i+1<n.length?n.");
    res.write("charCodeAt(i+1):0,t>=55296&&56319>=t&&r>=56320&&57343>=r&&(t=65536+((1");
    res.write("023&t)<<10)+(1023&r),i++),127>=t?e+=String.fromCharCode(t):2047>=t?e+=");
    res.write("String.fromCharCode(192|t>>>6&31,128|63&t):65535>=t?e+=String.fromChar");
    res.write("Code(224|t>>>12&15,128|t>>>6&63,128|63&t):2097151>=t&&(e+=String.fromC");
    res.write("harCode(240|t>>>18&7,128|t>>>12&63,128|t>>>6&63,128|63&t));return e}fu");
    res.write("nction str2rstr_utf16le(n){for(var t='',r=0;r<n.length;r++)t+=String.f");
    res.write("romCharCode(255&n.charCodeAt(r),n.charCodeAt(r)>>>8&255);return t}func");
    res.write("tion str2rstr_utf16be(n){for(var t='',r=0;r<n.length;r++)t+=String.fro");
    res.write("mCharCode(n.charCodeAt(r)>>>8&255,255&n.charCodeAt(r));return t}functi");
    res.write("on rstr2binb(n){for(var t=Array(n.length>>2),r=0;r<t.length;r++)t[r]=0");
    res.write(";for(var r=0;r<8*n.length;r+=8)t[r>>5]|=(255&n.charCodeAt(r/8))<<24-r%");
    res.write("32;return t}function binb2rstr(n){for(var t='',r=0;r<32*n.length;r+=8)");
    res.write("t+=String.fromCharCode(n[r>>5]>>>24-r%32&255);return t}function binb_s");
    res.write("ha512(n,t){void 0==sha512_k&&(sha512_k=new Array(new int64(1116352408,");
    res.write("-685199838),new int64(1899447441,602891725),new int64(-1245643825,-330");
    res.write("482897),new int64(-373957723,-2121671748),new int64(961987163,-2133388");
    res.write("24),new int64(1508970993,-1241133031),new int64(-1841331548,-135729571");
    res.write("7),new int64(-1424204075,-630357736),new int64(-670586216,-1560083902)");
    res.write(",new int64(310598401,1164996542),new int64(607225278,1323610764),new i");
    res.write("nt64(1426881987,-704662302),new int64(1925078388,-226784913),new int64");
    res.write("(-2132889090,991336113),new int64(-1680079193,633803317),new int64(-10");
    res.write("46744716,-815192428),new int64(-459576895,-1628353838),new int64(-2727");
    res.write("42522,944711139),new int64(264347078,-1953704523),new int64(604807628,");
    res.write("2007800933),new int64(770255983,1495990901),new int64(1249150122,18564");
    res.write("31235),new int64(1555081692,-1119749164),new int64(1996064986,-2096016");
    res.write("459),new int64(-1740746414,-295247957),new int64(-1473132947,766784016)");
    res.write(",new int64(-1341970488,-1728372417),new int64(-1084653625,-1091629340),");
    res.write("new int64(-958395405,1034457026),new int64(-710438585,-1828018395),new ");
    res.write("int64(113926993,-536640913),new int64(338241895,168717936),new int64(66");
    res.write("6307205,1188179964),new int64(773529912,1546045734),new int64(129475737");
    res.write("2,1522805485),new int64(1396182291,-1651133473),new int64(1695183700,-1");
    res.write("951439906),new int64(1986661051,1014477480),new int64(-2117940946,12067");
    res.write("59142),new int64(-1838011259,344077627),new int64(-1564481375,129086346");
    res.write("0),new int64(-1474664885,-1136513023),new int64(-1035236496,-789014639)");
    res.write(",new int64(-949202525,106217008),new int64(-778901479,-688958952),new i");
    res.write("nt64(-694614492,1432725776),new int64(-200395387,1467031594),new int64(");
    res.write("275423344,851169720),new int64(430227734,-1194143544),new int64(5069486");
    res.write("16,1363258195),new int64(659060556,-544281703),new int64(883997877,-509");
    res.write("917016),new int64(958139571,-976659869),new int64(1322822218,-482243893");
    res.write("),new int64(1537002063,2003034995),new int64(1747873779,-692930397),new");
    res.write(" int64(1955562222,1575990012),new int64(2024104815,1125592928),new int6");
    res.write("4(-2067236844,-1578062990),new int64(-1933114872,442776044),new int64(-");
    res.write("1866530822,593698344),new int64(-1538233109,-561857047),new int64(-1090");
    res.write("935817,-1295615723),new int64(-965641998,-479046869),new int64(-9033976");
    res.write("82,-366583396),new int64(-779700025,566280711),new int64(-354779690,-84");
    res.write("0897762),new int64(-176337025,-294727304),new int64(116418474,191413855");
    res.write("4),new int64(174292421,-1563912026),new int64(289380356,-1090974290),ne");
    res.write("w int64(460393269,320620315),new int64(685471733,587496836),new int64(8");
    res.write("52142971,1086792851),new int64(1017036298,365543100),new int64(11260005");
    res.write("80,-1676669620),new int64(1288033470,-885112138),new int64(1501505948,-");
    res.write("60457430),new int64(1607167915,987167468),new int64(1816402316,12461895");
    res.write("91)));var r,e,i=new Array(new int64(1779033703,-205731576),new int64(-1");
    res.write("150833019,-2067093701),new int64(1013904242,-23791573),new int64(-15214");
    res.write("86534,1595750129),new int64(1359893119,-1377402159),new int64(-16941443");
    res.write("72,725511199),new int64(528734635,-79577749),new int64(1541459225,32703");
    res.write("3209)),h=new int64(0,0),a=new int64(0,0),o=new int64(0,0),w=new int64(0");
    res.write(",0),l=new int64(0,0),c=new int64(0,0),s=new int64(0,0),f=new int64(0,0)");
    res.write(",d=new int64(0,0),u=new int64(0,0),_=new int64(0,0),b=new int64(0,0),g=");
    res.write("new int64(0,0),y=new int64(0,0),v=new int64(0,0),C=new int64(0,0),A=new");
    res.write(" int64(0,0),p=new Array(80);for(e=0;80>e;e++)p[e]=new int64(0,0);for(n[");
    res.write("t>>5]|=128<<24-(31&t),n[(t+128>>10<<5)+31]=t,e=0;e<n.length;e+=32){for(");
    res.write("int64copy(o,i[0]),int64copy(w,i[1]),int64copy(l,i[2]),int64copy(c,i[3])");
    res.write(",int64copy(s,i[4]),int64copy(f,i[5]),int64copy(d,i[6]),int64copy(u,i[7]");
    res.write("),r=0;16>r;r++)p[r].h=n[e+2*r],p[r].l=n[e+2*r+1];for(r=16;80>r;r++)int6");
    res.write("4rrot(v,p[r-2],19),int64revrrot(C,p[r-2],29),int64shr(A,p[r-2],6),b.l=v");
    res.write(".l^C.l^A.l,b.h=v.h^C.h^A.h,int64rrot(v,p[r-15],1),int64rrot(C,p[r-15],8");
    res.write("),int64shr(A,p[r-15],7),_.l=v.l^C.l^A.l,_.h=v.h^C.h^A.h,int64add4(p[r],");
    res.write("b,p[r-7],_,p[r-16]);for(r=0;80>r;r++)g.l=s.l&f.l^~s.l&d.l,g.h=s.h&f.h^~");
    res.write("s.h&d.h,int64rrot(v,s,14),int64rrot(C,s,18),int64revrrot(A,s,9),b.l=v.l");
    res.write("^C.l^A.l,b.h=v.h^C.h^A.h,int64rrot(v,o,28),int64revrrot(C,o,2),int64rev");
    res.write("rrot(A,o,7),_.l=v.l^C.l^A.l,_.h=v.h^C.h^A.h,y.l=o.l&w.l^o.l&l.l^w.l&l.l");
    res.write(",y.h=o.h&w.h^o.h&l.h^w.h&l.h,int64add5(h,u,b,g,sha512_k[r],p[r]),int64a");
    res.write("dd(a,_,y),int64copy(u,d),int64copy(d,f),int64copy(f,s),int64add(s,c,h),");
    res.write("int64copy(c,l),int64copy(l,w),int64copy(w,o),int64add(o,h,a);int64add(i");
    res.write("[0],i[0],o),int64add(i[1],i[1],w),int64add(i[2],i[2],l),int64add(i[3],i");
    res.write("[3],c),int64add(i[4],i[4],s),int64add(i[5],i[5],f),int64add(i[6],i[6],d");
    res.write("),int64add(i[7],i[7],u)}var m=new Array(16);for(e=0;8>e;e++)m[2*e]=i[e]");
    res.write(".h,m[2*e+1]=i[e].l;return m}function int64(n,t){this.h=n,this.l=t}funct");
    res.write("ion int64copy(n,t){n.h=t.h,n.l=t.l}function int64rrot(n,t,r){n.l=t.l>>>");
    res.write("r|t.h<<32-r,n.h=t.h>>>r|t.l<<32-r}function int64revrrot(n,t,r){n.l=t.h>");
    res.write(">>r|t.l<<32-r,n.h=t.l>>>r|t.h<<32-r}function int64shr(n,t,r){n.l=t.l>>>");
    res.write("r|t.h<<32-r,n.h=t.h>>>r}function int64add(n,t,r){var e=(65535&t.l)+(655");
    res.write("35&r.l),i=(t.l>>>16)+(r.l>>>16)+(e>>>16),h=(65535&t.h)+(65535&r.h)+(i>>");
    res.write(">16),a=(t.h>>>16)+(r.h>>>16)+(h>>>16);n.l=65535&e|i<<16,n.h=65535&h|a<<");
    res.write("16}function int64add4(n,t,r,e,i){var h=(65535&t.l)+(65535&r.l)+(65535&e");
    res.write(".l)+(65535&i.l),a=(t.l>>>16)+(r.l>>>16)+(e.l>>>16)+(i.l>>>16)+(h>>>16),");
    res.write("o=(65535&t.h)+(65535&r.h)+(65535&e.h)+(65535&i.h)+(a>>>16),w=(t.h>>>16)");
    res.write("+(r.h>>>16)+(e.h>>>16)+(i.h>>>16)+(o>>>16);n.l=65535&h|a<<16,n.h=65535&");
    res.write("o|w<<16}function int64add5(n,t,r,e,i,h){var a=(65535&t.l)+(65535&r.l)+(");
    res.write("65535&e.l)+(65535&i.l)+(65535&h.l),o=(t.l>>>16)+(r.l>>>16)+(e.l>>>16)+(");
    res.write("i.l>>>16)+(h.l>>>16)+(a>>>16),w=(65535&t.h)+(65535&r.h)+(65535&e.h)+(65");
    res.write("535&i.h)+(65535&h.h)+(o>>>16),l=(t.h>>>16)+(r.h>>>16)+(e.h>>>16)+(i.h>>");
    res.write(">16)+(h.h>>>16)+(w>>>16);n.l=65535&a|o<<16,n.h=65535&w|l<<16}var hexcas");
    res.end("e=0,b64pad='';var sha512_k;");
}





