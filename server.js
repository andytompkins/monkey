var logManager = require('simple-node-logger');
var exec = require('child_process').execSync;
var express = require('express');
var compression = require('compression');
var _ = require('lodash');
var fs = require('fs');
var path = require('path');
var passport = require('passport');
var CustomStrategy = require('passport-custom').Strategy;
var bodyParser = require('body-parser');
var urlencode = require('urlencode');
var json = require('json-middleware').middleware();
//var cookieParser = require('cookie-parser');
var session = require('express-session');
var FileStore = require('session-file-store')(session);


var audit = logManager.createSimpleFileLogger('audit.log');
audit.setLevel('info');
var log = logManager.createSimpleLogger();
log.setLevel('debug');

var configFile = 'settings.json';
var config = JSON.parse(fs.readFileSync(configFile));
var home = config.home || '/home';

var app = express();
app.use(express.static(path.join(__dirname, '/assets')));
app.use(compression());
//app.use(cookieParser);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
  secret: 'chattymonkey',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 },
  store: new FileStore()
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new CustomStrategy(function(req, done) {
  log.debug("CustomStrategy");
  var users = fs.readdirSync(home).filter(function(f) {
    return fs.statSync(path.join(home, f)).isDirectory();
  });
  var u = _.find(users, function(user) {
    return user === req.body.username;
  });
  if (!u) {
    return done(null, false, { message: "Invalid username or password." });
  }
  if (!req.body.password) {
    return done(null, false, { message: "Empty password." });
  }
  
  var pub = u + '.pub';
  var pkcs = u + '.pkcs';
  var sig = u + '.sig';
  
  var decodeSig = 'base64 -d > ' + sig;
  try {
    exec(decodeSig, { input: req.body.password });
  }
  catch (err) {
    log.debug("Signature decode failed");
    return done(null, false, { message: "Invalid username or password." });
  }
  
  audit.info("Reading authorized keys of user " + u);
  var getKeys = 'sudo su - ' + u + ' -c "cat ~/.ssh/authorized_keys"';
  try {
    var stdout = exec(getKeys);
  }
  catch (err) {
    log.debug("Reading of authorized keys failed");
    return done(null, false, { message: "Invalid username or password." });
  }
  var lines = stdout.toString().split('\n');
  if (lines.length > 0) {
    for (var i = 0; i < lines.length; i++) {
      fs.writeFileSync(pub, lines[i]);
      var convert2Pkcs = 'ssh-keygen -e -f ' + pub + ' -m PKCS8 > ' + pkcs;
      try {
        exec(convert2Pkcs);
      }
      catch (err) {
        log.debug("Public key conversion to PKCS8 failed");
        return done(null, false, { message: "Invalid username or password." });
      }
      // openssl is weird, and returns a status code of 1 on success so this will always throw
      var verifySig = 'openssl pkeyutl -verify -pubin -inkey ' + pkcs + ' -in unlock.txt -sigfile ' + sig;
      try {
        stdout = exec(verifySig);
      }
      catch (err) {
        stdout = err.stdout.toString();
        if (err.status === 1 && stdout.trim() === 'Signature Verified Successfully') {
          return done(null, { 'username': u });
        }
        
        console.dir(err);
        log.debug("Signature verification failed");
        log.debug("Output: " + stdout);
        log.debug("Error message: " + err.message);
        log.debug("Stack: " + err.stack);
        
        return done(null, false, { message: "Invalid username or password." });
      }
      
    }
    return done(null, false, { message: "Invalid username or password." });
  } else {
    log.info('User ' + u + ' has no authorized keys.');
    return done(null, false, { message: "Invalid username or password." });
  }
  
  return;
}));

passport.serializeUser(function(user, done) {
  //log.debug("serializeUser: " + user);
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  //log.debug("deserializeUser: " + user);
  done(null, user);
});

var router = express.Router();
app.set('view engine', 'jade');
app.set('views', __dirname + '/views');


router.get('/', function(req, res) {
  log.debug('rendering index');
  
  //console.dir(req.user);
  //console.log("==========");
  //console.dir(req.session);
  //var u = req.session.passport.user.username;
  
  var u = null;
  if (req.user && req.user.username) {
    u = req.user.username;
  } else if (req.session && req.session.passport && req.session.passport.user && req.session.passport.user.username) {
    u = req.session.passport.user.username;
  }
  
  var keys = [];
  
  if (u) {
  
    log.debug("got username " + u + " from passport");
    audit.info("Reading authorized keys of user " + u);
    var getKeys = 'sudo su - ' + u + ' -c "cat ~/.ssh/authorized_keys"';
    try {
      var stdout = exec(getKeys);
    }
    catch (err) {
      log.debug("Reading of authorized keys failed");
      //
    }
    //log.debug("stdout is " + stdout.toString());
    var lines = stdout.toString().split('\n');
    //console.dir(lines);
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].trim().length === 0) { continue; }
      
      var getFingerprint = 'ssh-keygen -lf /dev/stdin <<<"' + lines[i] + '"';
      try {
        stdout = exec(getFingerprint);
      }
      catch (err) {
        log.debug("Fingerprinting of key failed");
        //
      }
      var fingerprint = stdout.toString();
      var parts = fingerprint.split(/\s/);
      //console.dir(parts);
      keys.push({
        type: parts[3],
        key: parts[1],
        label: parts[2]
        size: parts[0]
      });
    }
    
  }
  console.dir(keys);
	res.render('index', { "keys": keys });
});

router.get('/login', function(req, res) {
  log.debug('rendering login');
  res.render('login', {});
});

router.post('/login', passport.authenticate('custom', {
  successRedirect: '/',
  failureRedirect: '/login'
}), function(req, res) {
  log.debug('processing login');
});


app.use(router);

var port = process.env.PORT || config.port || 3000;
var server = app.listen(port, function() {
  log.info("monkey listening on port " + port);
});



