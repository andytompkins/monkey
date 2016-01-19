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
var fingerprint = require('ssh-fingerprint');


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

var isAdmin = function(username) {
  var admin = _.find(config.admins, function(user) {
    return user === username;
  });
  if(!admin) {
    return false;
  }
  return true;
};

var getUsername = function(req) {
  var u = null;
  if (req.user && req.user.username) {
    u = req.user.username;
  } else if (req.session && req.session.passport && req.session.passport.user && req.session.passport.user.username) {
    u = req.session.passport.user.username;
  }
  return u;
};

var getUsers = function() {
  return fs.readdirSync(home).filter(function(f) {
    return fs.statSync(path.join(home, f)).isDirectory();
  });
};

var getKeys = function(username) {
  audit.info("Reading authorized keys of user " + username);
  var cmd = 'sudo su - ' + username + ' -c "cat ~/.ssh/authorized_keys"';
  try {
    var stdout = exec(cmd);
  }
  catch (err) {
    log.debug("Reading of authorized keys failed");
    return done(null, false, { message: "Invalid username or password." });
  }
  return stdout.toString().split('\n');
};

var addKey = function(username, key) {
  audit.info("Adding to " + username + " authorized_keys file, key: " + key);
  var cmd = 'sudo su - ' + username + ' -c "cat - >>~/.ssh/authorized_keys"';
  try {
    exec(cmd, { input: key });
  }
  catch (err) {
    var stdout = err.stdout.toString();        
    log.debug("Append to authorized_keys failed");
    log.debug("Output: " + stdout);
    log.debug("Error message: " + err.message);
    log.debug("Stack: " + err.stack);  
  }
};

var deleteKey = function(username, key) {
  var keyParts = key.split(/\s/);
  var lines = getKeys(username);
  for (var i = 0; i < lines.length; i++) {
    var parts = lines[i].split(/\s/);
    if (parts[0] === keyParts[0] && parts[1] === keyParts[1] && parts[2] === keyParts[2]) {
      audit.info("Deleting from " + username + " authorized_keys file, key: " + key);
      var n = i + 1;
      var cmd = 'sudo su - ' + username + ' -c "sed -i -e\"' + n + 'd\" ~/.ssh/authorized_keys"';
      log.debug("cmd is " + cmd);
      try {
        exec(cmd);
      }
      catch (err) {
        var stdout = err.stdout.toString();        
        log.debug("Delete from authorized_keys failed");
        log.debug("Output: " + stdout);
        log.debug("Error message: " + err.message);
        log.debug("Stack: " + err.stack);  
      }
      return;
    }
  }
  
};

var editKey = function(username, oldKey, newKey) {
  var keyParts = oldKey.split(/\s/);
  var lines = getKeys(username);
  for (var i = 0; i < lines.length; i++) {
    var parts = lines[i].split(/\s/);
    if (parts[0] === keyParts[0] && parts[1] === keyParts[1] && parts[2] === keyParts[2]) {
      audit.info("Editing " + username + " authorized_keys file, replacing key: " + oldKey + " with new key: " + newKey);
      var n = i + 1;
      var escapedKey = newKey.replace("/", "\/");
      var cmd = 'sudo su - ' + username + ' -c "sed -i -e\"' + n + 's/.*/' + escapedKey + '/\" ~/.ssh/authorized_keys"';
      log.debug("cmd is " + cmd);
      try {
        exec(cmd);
      }
      catch (err) {
        var stdout = err.stdout.toString();        
        log.debug("Delete from authorized_keys failed");
        log.debug("Output: " + stdout);
        log.debug("Error message: " + err.message);
        log.debug("Stack: " + err.stack);  
      }
      return;
    }
  }
  
  
};

passport.use(new CustomStrategy(function(req, done) {
  log.debug("CustomStrategy");
  //var users = fs.readdirSync(home).filter(function(f) {
  //  return fs.statSync(path.join(home, f)).isDirectory();
  //});
  var users = getUsers();
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
  
  var lines = getKeys(u);
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
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});

var data = {};
app.use(function(req, res, next) {
  data = {};
  var u = getUsername(req);
  if (req.path === '/login' || u) {
    data.username = u;
    data.isAdmin = isAdmin(u);
    return next();
  }
  res.redirect('/login');
});

var router = express.Router();
app.set('view engine', 'jade');
app.set('views', __dirname + '/views');

router.get('/', function(req, res) {
  log.debug('rendering index');

  var u = getUsername(req);  
  var keys = [];
  if (u) {
  
    log.debug("got username " + u + " from passport");
    
    var lines = getKeys(u);
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].trim().length === 0) { continue; }
      
      var parts = lines[i].split(/\s/);
      var keyPrint = fingerprint(parts[1]);
      
      keys.push({
        type: parts[0],
        key: parts[1],
        label: parts[2],
        fingerprint: keyPrint
      });
    }
    
  }
  data.keys = keys;
  res.render('index', data);
	//res.render('index', { "keys": keys, "isAdmin": isAdmin(u) });
});

router.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/login');
});

router.get('/login', function(req, res) {
  log.debug('rendering login');
  res.render('login', data);
});

router.post('/login', passport.authenticate('custom', {
  successRedirect: '/',
  failureRedirect: '/login'
}), function(req, res) {
  log.debug('processing login');
});

router.get('/users', function(req, res) {
  var u = getUsername(req);
  var admin = isAdmin(u);
  if (!admin) {
    return res.redirect('/');
  }
  //var users = getUsers();
  data.users = getUsers();
  res.render('users', data);
});

router.post('/forms/addkey', function(req, res) {
  res.render('addkeyform', data);
});
router.post('/forms/editkey', function(req, res) {
  data.type = req.body.type;
  data.key = req.body.key;
  data.label = req.body.label;
  data.fullKey = req.body.type + " " + req.body.key + " " + req.body.label;
  res.render('editkeyform', data);
});
router.post('/forms/deletekey', function(req, res) {
  data.fullKey = req.body.type + " " + req.body.key + " " + req.body.label;
  res.render('deletekeyform', data);
});

router.post('/addkey', function(req, res) {
  var u = getUsername(req);
  addKey(u, req.body.publickey);
  res.redirect('/');
});

router.post('/editkey', function(req, res) {
  var u = getUsername(req);
  console.dir(req.body);
  var newKey = req.body.type + " " + req.body.key + " " + req.body.label;
  editKey(u, req.body.publickey, newKey);
  res.redirect('/');
})

app.use(router);

var port = process.env.PORT || config.port || 3000;
var server = app.listen(port, function() {
  log.info("monkey listening on port " + port);
});



