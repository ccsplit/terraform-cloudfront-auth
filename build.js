const shell = require('shelljs');
const prompt = require('prompt');
const fs = require('fs');
const axios = require('axios');
const colors = require('colors/safe');
const url = require('url');
const R = require('ramda');
const argv = require('minimist')(process.argv.slice(2));
var config = { AUTH_REQUEST: {}, TOKEN_REQUEST: {} };
var oldConfig;

prompt.message = colors.blue(">");
prompt.override = argv;

prompt.start();
prompt.get({
  properties: {
    CLOUDFRONT_DISTRIBUTION: {
      message: colors.red("Enter distribution name"),
      required: true
    },
    AUTH_VENDOR: {
      description: colors.red("Authentication methods:\n    (1) Google\n    (2) Microsoft\n    (3) GitHub\n    (4) OKTA\n    (5) Auth0\n    (6) Centrify\n\n (7) Onelogin    Select an authentication method")
    }
  }
}, function (err, result) {
  config.DISTRIBUTION = result.CLOUDFRONT_DISTRIBUTION;
  shell.mkdir('-p', 'distributions/' + config.DISTRIBUTION);
  if (fs.existsSync('distributions/' + config.DISTRIBUTION + '/config.json')) {
    oldConfig = JSON.parse(fs.readFileSync('./distributions/' + config.DISTRIBUTION + '/config.json', 'utf8'));
  }
  if (!fs.existsSync('distributions/' + config.DISTRIBUTION + '/id_rsa') || !fs.existsSync('./distributions/' + config.DISTRIBUTION + '/id_rsa.pub')) {
    shell.exec("ssh-keygen -t rsa -m PEM -b 4096 -f ./distributions/" + config.DISTRIBUTION + "/id_rsa -N ''");
    shell.exec("openssl rsa -in ./distributions/" + config.DISTRIBUTION + "/id_rsa -pubout -outform PEM -out ./distributions/" + config.DISTRIBUTION + "/id_rsa.pub");
  }
  switch (result.AUTH_VENDOR) {
    case 'google':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "GOOGLE") {
        oldConfig = undefined;
      }
      config.AUTHN = "GOOGLE";
      googleConfiguration();
      break;
    case 'microsoft':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "MICROSOFT") {
        oldConfig = undefined;
      }
      config.AUTHN = "MICROSOFT";
      microsoftConfiguration();
      break;
    case 'github':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "GITHUB") {
        oldConfig = undefined;
      }
      config.AUTHN = "GITHUB";
      githubConfiguration();
      break;
    case 'okta':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "OKTA") {
        oldConfig = undefined;
      }
      config.AUTHN = "OKTA";
      oktaConfiguration();
      break;
    case 'auth0':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "AUTH0") {
        oldConfig = undefined;
      }
      config.AUTHN = "AUTH0";
      auth0Configuration();
      break;
    case 'centrify':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "CENTRIFY") {
        oldConfig = undefined;
      }
      config.AUTHN = "CENTRIFY";
      centrifyConfiguration();
      break;
    case 'onelogin':
      if (R.pathOr('', ['AUTHN'], oldConfig) != "ONELOGIN"){
        oldConfig = undefined;
      }
      config.AUTHN = "ONELOGIN";
      oneloginConfiguration();
      break;
    default:
      console.log("Method not recognized. Stopping build...");
      process.exit(1);
  }
});

function microsoftConfiguration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      TENANT: {
        message: colors.red("Tenant"),
        required: true,
        default: R.pathOr('', ['TENANT'], oldConfig)
      },
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      SESSION_DURATION: {
        message: colors.red("Session Duration (hours)"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      },
      AUTHZ: {
        description: colors.red("Authorization methods:\n   (1) Azure AD Login (default)\n   (2) JSON Username Lookup\n\n   Select an authorization method")
      }
    }
  }, function(err, result) {
    config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
    config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
    config.TENANT = result.TENANT;
    config.DISCOVERY_DOCUMENT = 'https://login.microsoftonline.com/' + result.TENANT + '/.well-known/openid-configuration';
    config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;

    config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;

    config.AUTH_REQUEST.client_id = result.CLIENT_ID;
    config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.AUTH_REQUEST.response_type = 'code';
    config.AUTH_REQUEST.response_mode = 'query';
    config.AUTH_REQUEST.scope = 'openid';

    config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
    config.TOKEN_REQUEST.grant_type = 'authorization_code';
    config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;

    config.AUTHZ = result.AUTHZ;

    shell.cp('./authz/microsoft.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
    shell.cp('./authn/openid.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
    shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');

    fs.writeFileSync('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4));

    switch (result.AUTHZ) {
      case '1':
        shell.cp('./authz/microsoft.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
        writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
        break;
      case '2':
        shell.cp('./authz/microsoft.json-username-lookup.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
        prompt.start();
        prompt.message = colors.blue(">>>");
        prompt.get({
          properties: {
            JSON_USERNAME_LOOKUP: {
              description: colors.red("JSON username lookup endpoint"),
              default: R.pathOr('', ['JSON_USERNAME_LOOKUP'], oldConfig)
            }
          }
        }, function (err, result) {
          config.JSON_USERNAME_LOOKUP = result.JSON_USERNAME_LOOKUP;
          writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
        });
        break;
      default:
        console.log("Method not recognized. Stopping build...");
    }
  });
}

function googleConfiguration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      HD: {
        message: colors.red("Hosted Domain"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'hd'], oldConfig)
      },
      SESSION_DURATION: {
        pattern: /^[0-9]*$/,
        description: colors.red("Session Duration (hours)"),
        message: colors.green("Entry must only contain numbers"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      },
      AUTHZ: {
        description: colors.red("Authorization methods:\n   (1) Hosted Domain - verify email's domain matches that of the given hosted domain\n   (2) HTTP Email Lookup - verify email exists in JSON array located at given HTTP endpoint\n   (3) Google Groups Lookup - verify email exists in one of given Google Groups\n\n   Select an authorization method")
      }
    }
  }, function(err, result) {
    config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
    config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
    config.DISCOVERY_DOCUMENT = 'https://accounts.google.com/.well-known/openid-configuration';
    config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;

    config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;
    config.HOSTED_DOMAIN = result.HD;

    config.AUTH_REQUEST.client_id = result.CLIENT_ID;
    config.AUTH_REQUEST.response_type = 'code';
    config.AUTH_REQUEST.scope = 'openid email';
    config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.AUTH_REQUEST.hd = result.HD;

    config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
    config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;
    config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.TOKEN_REQUEST.grant_type = 'authorization_code';

    config.AUTHZ = result.AUTHZ;

    shell.cp('./authn/openid.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
    shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');

    fs.writeFileSync('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4));

    switch (parseInt(result.AUTHZ)) {
      case 1:
        shell.cp('./authz/google.hosted-domain.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
        shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');
        writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
        break;
      case 2:
        shell.cp('./authz/google.json-email-lookup.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
        prompt.start();
        prompt.message = colors.blue(">>>");
        prompt.get({
          properties: {
            JSON_EMAIL_LOOKUP: {
              description: colors.red("JSON email lookup endpoint"),
              default: R.pathOr('', ['JSON_EMAIL_LOOKUP'], oldConfig)
            }
          }
        }, function (err, result) {
          config.JSON_EMAIL_LOOKUP = result.JSON_EMAIL_LOOKUP;
          writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
        });
        break;
      case 3:
        prompt.start();
        prompt.message = colors.blue(">>>");
        prompt.get({
          properties: {
            MOVE: {
              message: colors.red("Place ") + colors.blue("google-authz.json") + colors.red(" file into ") + colors.blue("distributions/" + config.DISTRIBUTION) + colors.red(" folder. Press enter when done")
            }
          }
        }, function (err, result) {
          if (!shell.test('-f', 'distributions/' + config.DISTRIBUTION + '/google-authz.json')) {
            console.log('Need google-authz.json to use google groups authentication. Stopping build...');
          } else {
            var googleAuthz = JSON.parse(fs.readFileSync('distributions/' + config.DISTRIBUTION + '/google-authz.json'));
            if (!googleAuthz.hasOwnProperty('cloudfront_authz_groups')) {
              console.log('google-authz.json is missing cloudfront_authz_groups. Stopping build...');
            } else {
              shell.cp('./authz/google.groups-lookup.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
              googleGroupsConfiguration();
            }
          }
        });
        break;
      default:
        console.log("Method not recognized. Stopping build...");
    }
  });
}

function googleGroupsConfiguration() {
  prompt.start();
  prompt.message = colors.blue(">>>");
  prompt.get({
    properties: {
      SERVICE_ACCOUNT_EMAIL: {
        description: colors.red("Service Account Email"),
        required: true,
        default: R.pathOr('', ['SERVICE_ACCOUNT_EMAIL'], oldConfig)
      }
    }
  }, function (err, result) {
    config.SERVICE_ACCOUNT_EMAIL = result.SERVICE_ACCOUNT_EMAIL;
    writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'google-authz.json']);
  });
}

function oktaConfiguration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      BASE_URL: {
        message: colors.red("Base URL"),
        required: true,
        default: R.pathOr('', ['BASE_URL'], oldConfig)
      },
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      SESSION_DURATION: {
        pattern: /^[0-9]*$/,
        description: colors.red("Session Duration (hours)"),
        message: colors.green("Entry must only contain numbers"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      }
    }
  }, function(err, result) {
    config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
    config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
    config.DISCOVERY_DOCUMENT = result.BASE_URL + '/.well-known/openid-configuration';
    config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;

    config.BASE_URL = result.BASE_URL;
    config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;

    config.AUTH_REQUEST.client_id = result.CLIENT_ID;
    config.AUTH_REQUEST.response_type = 'code';
    config.AUTH_REQUEST.scope = 'openid email';
    config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;

    config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
    config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;
    config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.TOKEN_REQUEST.grant_type = 'authorization_code';

    config.AUTHZ = "OKTA";

    shell.cp('./authn/openid.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
    shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');

    fs.writeFileSync('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4));

    shell.cp('./authz/okta.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
    writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
  });
}

function githubConfiguration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      SESSION_DURATION: {
        pattern: /^[0-9]*$/,
        description: colors.red("Session Duration (hours)"),
        message: colors.green("Entry must only contain numbers"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      },
      GITHUB_ORGANIZATION: {
        description: colors.red("Organization"),
        required: true,
        default: R.pathOr('', ['ORGANIZATION'], oldConfig)
      }
    }
  }, function(err, result) {
    axios.get('https://api.github.com/orgs/' + result.GITHUB_ORGANIZATION)
      .then(function (response) {
        if (response.status == 200) {
          config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
          config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
          config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;
          config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;
          config.ORGANIZATION = result.GITHUB_ORGANIZATION;
          config.AUTHORIZATION_ENDPOINT = 'https://github.com/login/oauth/authorize';
          config.TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token';

          config.AUTH_REQUEST.client_id = result.CLIENT_ID;
          config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;
          config.AUTH_REQUEST.scope = 'read:org user:email';

          config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
          config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;
          config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;

          shell.cp('./authz/github.membership-lookup.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
          shell.cp('./authn/github.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
          writeConfig(config, zip, ['config.json', 'index.js', 'auth.js']);
        } else {
          console.log("Organization could not be verified (code " + response.status + "). Stopping build...");
        }
      })
      .catch(function(error) {
        console.log("Organization could not be verified. Stopping build... (" + error.message + ")");
      });
  });
}

// Auth0 configuration
function auth0Configuration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      BASE_URL: {
        message: colors.red("Base URL"),
        required: true,
        default: R.pathOr('', ['BASE_URL'], oldConfig)
      },
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      SESSION_DURATION: {
        pattern: /^[0-9]*$/,
        description: colors.red("Session Duration (hours)"),
        message: colors.green("Entry must only contain numbers"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      }
    }
  }, function(err, result) {
    config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
    config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
    config.DISCOVERY_DOCUMENT = result.BASE_URL + '/.well-known/openid-configuration';
    config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;

    config.BASE_URL = result.BASE_URL;
    config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;

    config.AUTH_REQUEST.client_id = result.CLIENT_ID;
    config.AUTH_REQUEST.response_type = 'code';
    config.AUTH_REQUEST.scope = 'openid email';
    config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;

    config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
    config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;
    config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.TOKEN_REQUEST.grant_type = 'authorization_code';

    config.AUTHZ = "AUTH0";

    shell.cp('./authn/openid.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
    shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');

    fs.writeFileSync('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4));

    shell.cp('./authz/auth0.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
    writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
  });
}

// Centrify configuration
function centrifyConfiguration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      BASE_URL: {
        message: colors.red("Base URL"),
        required: true,
        default: R.pathOr('', ['BASE_URL'], oldConfig)
      },
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      SESSION_DURATION: {
        pattern: /^[0-9]*$/,
        description: colors.red("Session Duration (hours)"),
        message: colors.green("Entry must only contain numbers"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      }
    }
  }, function(err, result) {
    config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
    config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
    config.DISCOVERY_DOCUMENT = result.BASE_URL + '/.well-known/openid-configuration';
    config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;

    config.BASE_URL = result.BASE_URL;
    config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;

    config.AUTH_REQUEST.client_id = result.CLIENT_ID;
    config.AUTH_REQUEST.response_type = 'code';
    config.AUTH_REQUEST.scope = 'openid email';
    config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;

    config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
    config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;
    config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.TOKEN_REQUEST.grant_type = 'authorization_code';

    config.AUTHZ = "CENTRIFY";

    shell.cp('./authn/openid.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
    shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');

    fs.writeFileSync('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4));

    shell.cp('./authz/centrify.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
    writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
  });
}

// OneLogin configuration
function oneloginConfiguration() {
  prompt.message = colors.blue(">>");
  prompt.start();
  prompt.get({
    properties: {
      BASE_URL: {
        message: colors.red("Base URL"),
        required: true,
        default: R.pathOr('', ['BASE_URL'], oldConfig)
      },
      CLIENT_ID: {
        message: colors.red("Client ID"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'client_id'], oldConfig)
      },
      CLIENT_SECRET: {
        message: colors.red("Client Secret"),
        required: true,
        default: R.pathOr('', ['TOKEN_REQUEST', 'client_secret'], oldConfig)
      },
      REDIRECT_URI: {
        message: colors.red("Redirect URI"),
        required: true,
        default: R.pathOr('', ['AUTH_REQUEST', 'redirect_uri'], oldConfig)
      },
      SESSION_DURATION: {
        pattern: /^[0-9]*$/,
        description: colors.red("Session Duration (hours)"),
        message: colors.green("Entry must only contain numbers"),
        required: true,
        default: R.pathOr('', ['SESSION_DURATION'], oldConfig)/60/60
      }
    }
  }, function(err, result) {
    config.PRIVATE_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa', 'utf8');
    config.PUBLIC_KEY = fs.readFileSync('distributions/' + config.DISTRIBUTION + '/id_rsa.pub', 'utf8');
    config.DISCOVERY_DOCUMENT = result.BASE_URL + '/oidc/2/.well-known/openid-configuration';
    config.SESSION_DURATION = parseInt(result.SESSION_DURATION, 10) * 60 * 60;

    config.BASE_URL = result.BASE_URL;
    config.CALLBACK_PATH = url.parse(result.REDIRECT_URI).pathname;

    config.AUTH_REQUEST.client_id = result.CLIENT_ID;
    config.AUTH_REQUEST.response_type = 'code';
    config.AUTH_REQUEST.scope = 'openid email';
    config.AUTH_REQUEST.redirect_uri = result.REDIRECT_URI;

    config.TOKEN_REQUEST.client_id = result.CLIENT_ID;
    config.TOKEN_REQUEST.client_secret = result.CLIENT_SECRET;
    config.TOKEN_REQUEST.redirect_uri = result.REDIRECT_URI;
    config.TOKEN_REQUEST.grant_type = 'authorization_code';

    config.AUTHZ = "ONELOGIN";

    shell.cp('./authn/openid.index.js', './distributions/' + config.DISTRIBUTION + '/index.js');
    shell.cp('./nonce.js', './distributions/' + config.DISTRIBUTION + '/nonce.js');

    fs.writeFileSync('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4));

    shell.cp('./authz/onelogin.js', './distributions/' + config.DISTRIBUTION + '/auth.js');
    writeConfig(config, zip, ['config.json', 'index.js', 'auth.js', 'nonce.js']);
  });
}

function zip(files) {
  var filesString = '';
  for (var i = 0; i < files.length; i++) {
    filesString += ' distributions/' + config.DISTRIBUTION + '/' + files[i] + ' ';
  }
  shell.exec('zip -q distributions/' + config.DISTRIBUTION + '/' + config.DISTRIBUTION + '.zip ' + 'package-lock.json package.json -r node_modules');
  shell.exec('zip -q -r -j distributions/' + config.DISTRIBUTION + '/' + config.DISTRIBUTION + '.zip ' + filesString);
  console.log(colors.green("Done... created Lambda function distributions/" + config.DISTRIBUTION + "/" + config.DISTRIBUTION + ".zip"));
}

function writeConfig(result, callback, files) {
  fs.writeFile('distributions/' + config.DISTRIBUTION + '/config.json', JSON.stringify(result, null, 4), (err) => {
    if (err) throw err;
    callback(files);
  });
}
