var Hoek = require("hoek");
var UUID = require("node-uuid");

var internals = {};

exports.register = function(server, options, next){

    // TODO: validate the options with Joi
    // TODO: verify if there are any other options to the strategy

debugger;


/*
1) in the main options of the server, provide a catbox client (example: catbox-memory)

    server: {

        cache: {
            name: "sessionCache",
            engine: require("catbox-memory"),
            partition: "sessionCachePartition"
        }


2) in the options this this plugin, we must give:
    -the name of the catbox client configured above in the "cache" options (default: sessionCache)
    -the name of the segment in the "segment" optoins (default: sessionCacheSegment)
    -loginPath
    -logoutPath
    -validateLoginData
    -successRedirectTo

    -any other options for the auth strategy (which uses the "cookie" scheme)
    -any other option for the catbox policy
*/

    // create the catbox policy; the underlying catbox client is the one configured in the main
    // options of the server with the "sessionCache" name
    var sessionCache = server.cache({
        
        cache: options.cacheName || "sessionCache",  // the cache name configured in the main server options (an identifier of the catbox client)
        segment: options.cacheSegment || "sessionCacheSegment",

        // the max alowed value in catbox-memory
        expiresIn: options.ttl || Math.pow(2, 31) - 1
    });

    ///server.expose("sessionCache", sessionCache);

    // registers an authentication strategy named "session-cache" using the "cookie" scheme
    // (the scheme is provided by the hapi-auth-cookie plugin, which must be registered before this one)
    var strategyOptions = {
        password: options.ironPassword,
        validateFunc: function(request, session, callback) {
            debugger;

            // note: session[options.cookieName] is the uuid previously used in sessionCache.set
            var key = strategyOptions.cookie;
            sessionCache.get(session[key], function(err, value, cached, report) {
                debugger;

                // could not get the session data from catbox (internal error)
                if (err) {
                    return callback(err);
                }

                // session data in catbox is invalid or does not exist
                if (!cached) {
                    return callback(null, false);
                }

                return callback(null, true, value);
            });

            console.log(sessionCache.stats);
        }
    };
    

    console.log("options.redirectTo", options.redirectTo)
    debugger;
    Hoek.merge(strategyOptions, {
        cookie: options.cookieName || "sid",
        ttl: options.ttl,
        isSecure: options.isSecure,

        // if the session is expired, will delete the cookie in the browser (but if the cookie has expired, it will remain) - ???
        clearInvalid: options.clearInvalid, 
        redirectTo: options.redirectTo || options.loginPath,
        appendNext: options.appendNext,
        redirectOnTry: options.redirectOnTry,

    }, false);

    var mode = false;
    server.auth.strategy("session-cache", "cookie", mode, strategyOptions);

    // login route
    server.route({
        path: options.loginPath,
        method: "POST",
        config: {

            handler: function(request, reply) {
                debugger;

                if (request.auth.isAuthenticated) {
                    return reply.redirect(options.successRedirectTo);
                }

                // TODO: the logic to check the password should be extracted

                // sync method
                options.validateLoginData(request, function(err, loginData){

                    if(err){
                        if(err.output && err.output.statusCode === 401){
                            // the meaning of output.message is overloaded here
                            return reply.redirect(err.message);
                        }

                        return reply(err);
                    }

                    // we now set the session in the internal cache (Catbox with memory adapter)
                    var newSession = {
                        uuid: UUID.v4(),
                        loginData: loginData
                    };

                    // store an item in the cache
                    sessionCache.set(

                        // the unique item identifier 
                        newSession.uuid,

                        //  value to be stored
                        newSession,

                        // same value as the ttl in the cookie
                        strategyOptions.ttl || 0,
                        //10000,

                        function(err) {
                            debugger;

                            if (err) {
                                console.log(err.message);
                                return reply(err);
                            }

                            var cookieCrumb = {};
                            cookieCrumb[strategyOptions.cookie] = newSession.uuid;

                            request.cookieAuth.set(cookieCrumb);
                            
                            return reply.redirect(options.successRedirectTo);
                        }
                    );

                });

            },

            auth: {
                strategy: "session-cache",
                mode: "try"
            },

            plugins: {

                "hapi-auth-cookie": {
                    redirectTo: false
                }
            }

        }
    });

    // logout route
    server.route({
        path: options.logoutPath,
        method: "GET",
        config: {

            handler: function(request, reply) {

debugger;
                if(!request.auth.isAuthenticated){
                    return reply.redirect(options.loginPath);
                }

                var uuid;
                if(request.auth.artifacts){

                    uuid = request.auth.artifacts[strategyOptions.cookie];
                }

                sessionCache.drop(uuid, function(err){
debugger;
                    if(err){
                        return reply(err);
                    }

                    request.cookieAuth.clear();
                    return reply.redirect(options.loginPath);
                });
            },

            auth: {
                strategy: "session-cache",
                mode: "try"
            },

            plugins: {

                "hapi-auth-cookie": {
                    redirectTo: false
                }
            }
        }
    });

    return next();

};

exports.register.attributes = {
    name: "hapi-auth-session-cache",
    dependencies: ["hapi-auth-cookie"]
};
