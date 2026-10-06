import { Accounts } from 'meteor/accounts-base';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode-svg';
import { Meteor } from 'meteor/meteor';
import { check, Match } from 'meteor/check';
import { DDPRateLimiter } from 'meteor/ddp-rate-limiter';
import { EJSON } from 'meteor/ejson';

const validateChangeHooks = [];

const registerHook = (hooks, fn) => {
  hooks.push(fn);
  return {
    stop() {
      const index = hooks.indexOf(fn);
      if (index >= 0) {
        hooks.splice(index, 1);
      }
    },
  };
};

const runHooks = async (hooks, payload) => {
  for (const hook of [...hooks]) {
    await hook(payload);
  }
};

/**
 * @summary Reject an activation or a deactivation.
 * Throw a `Meteor.Error` from the callback to refuse the change and report
 * the reason to the user. Any other exception reaches the client as a 500
 * (`Internal server error`).
 * @locus Server
 * @param {Function} fn Receives `{ type, stage, user, connection }`.
 * `type` is `activation` or `deactivation`. When `type` is `activation`,
 * `stage` is `setup` (a secret is about to be issued) or `confirm` (2FA is
 * about to be turned on, including when it is already on).
 * @returns {{stop: Function}} Call `stop()` to remove the callback.
 */
Accounts.validate2faChange = fn => registerHook(validateChangeHooks, fn);

const TOTP_ALGORITHM = 'SHA1';
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30;
const TOTP_SECRET_SIZE = 20;
const DEFAULT_WINDOW = 10;
const DEFAULT_LOGIN_TYPES = ['password', 'passwordless'];
const TWO_FACTOR_METHODS = [
  'generate2faActivationQrCode',
  'enableUser2fa',
  'disableUser2fa',
];

const DEFAULT_CONFIG = {
  window: DEFAULT_WINDOW,
  preventReplay: true,
  loginTypes: DEFAULT_LOGIN_TYPES,
  rateLimit: { numRequests: 5, timeInterval: 60_000 },
  allowPlaintextSecrets: true,
};

let config = { ...DEFAULT_CONFIG };

const getOtpSecret = secret => OTPAuth.Secret.fromBase32(secret);

const getTotp = ({ issuer = '', label = 'OTPAuth', secret }) =>
  new OTPAuth.TOTP({
    issuer,
    label,
    secret: typeof secret === 'string' ? getOtpSecret(secret) : secret,
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD,
  });

const generateActivationData = ({ issuer, label }) => {
  const secret = new OTPAuth.Secret({ size: TOTP_SECRET_SIZE });
  const totp = getTotp({ issuer, label, secret });

  return {
    secret: secret.base32,
    uri: totp.toString(),
  };
};

/**
 * @summary Configure TOTP verification and replay protection.
 * Defaults match previous releases, except that a code cannot be reused.
 * @locus Server
 * @param {Object} options
 * @param {Number} [options.window=10] TOTP steps accepted on each side of the current step.
 * @param {Boolean} [options.preventReplay=true] Reject a step at or before the last accepted one.
 * @param {String[]} [options.loginTypes] Login attempt types that get replay protection. Replaces the default list.
 * @param {Object} [options.rateLimit] Per-user limit for the 2FA methods.
 * @param {Number} options.rateLimit.numRequests
 * @param {Number} options.rateLimit.timeInterval Interval in milliseconds.
 * @param {Boolean} [options.allowPlaintextSecrets=true] Accept secrets stored before encryption was enabled.
 */
Accounts.configure2fa = options => {
  check(options, {
    window: Match.Optional(Match.Where(w => {
      check(w, Match.Integer);
      if (w < 0) throw new Match.Error('accounts-2fa: window must be >= 0');
      return true;
    })),
    preventReplay: Match.Optional(Boolean),
    loginTypes: Match.Optional([String]),
    rateLimit: Match.Optional({
      numRequests: Match.Integer,
      timeInterval: Match.Integer,
    }),
    allowPlaintextSecrets: Match.Optional(Boolean),
  });

  const rateLimitChanged = options.rateLimit !== undefined;
  config = {
    ...config,
    ...options,
    rateLimit: options.rateLimit
      ? { ...options.rateLimit }
      : config.rateLimit,
  };
  if (rateLimitChanged && rateLimitRuleId) {
    applyRateLimit();
  }
};

const changeHooks = [];
const codeFailureHooks = [];

/**
 * @summary Called after 2FA is enabled, disabled or reset.
 * This package does not check who may call the server helpers. The app decides.
 * @locus Server
 * @param {Function} fn Receives `{ event, userId, connection }`. `event` is `enabled`, `disabled` or `reset`.
 */
Accounts.on2faChange = fn => registerHook(changeHooks, fn);

/**
 * @summary Called when a TOTP code is rejected.
 * @locus Server
 * @param {Function} fn Receives `{ userId, method }`.
 */
Accounts.on2faCodeFailure = fn => registerHook(codeFailureHooks, fn);

/**
 * @summary Remove 2FA from a user. Intended for an administrator recovery flow.
 * There is no permission check: this is not a method, and the app decides who may call it.
 * @locus Server
 * @param {String} userId
 * @param {Object} [options]
 */
Accounts.reset2faForUser = async (userId, options = {}) => {
  check(userId, String);
  await Meteor.users.updateAsync(userId, {
    $unset: { 'services.twoFactorAuthentication': 1 },
  });
  await runHooks(changeHooks, {
    event: 'reset',
    userId,
    connection: options.connection || null,
  });
};

const oauthEncryption = () => Package['oauth-encryption']?.OAuthEncryption;

const encryptSecret = plain => {
  const encryption = oauthEncryption();
  if (!encryption?.keyIsLoaded()) {
    return plain;
  }
  return encryption.seal(plain);
};

const decryptSecret = stored => {
  const encryption = oauthEncryption();
  if (encryption?.isSealed(stored)) {
    if (!encryption.keyIsLoaded()) {
      return null;
    }
    try {
      return encryption.open(stored);
    } catch (error) {
      return null;
    }
  }
  if (typeof stored === 'string' && stored.length > 0 && config.allowPlaintextSecrets) {
    return stored;
  }
  return null;
};

/**
 * @summary Encrypt secrets that are still stored in plaintext.
 * Skips a user whose secret changed after it was read.
 * @locus Server
 * @returns {Promise<Number>} Number of users migrated.
 */
Accounts.encryptExisting2faSecrets = async () => {
  if (!oauthEncryption()?.keyIsLoaded()) {
    throw new Error(
      'accounts-2fa: add oauth-encryption and set Accounts.config({ oauthSecretKey }) before encrypting existing secrets'
    );
  }
  const users = await Meteor.users
    .find(
      { 'services.twoFactorAuthentication.secret': { $exists: true } },
      { fields: { 'services.twoFactorAuthentication.secret': 1 } }
    )
    .fetchAsync();

  let migrated = 0;
  for (const user of users) {
    const secret = user.services?.twoFactorAuthentication?.secret;
    if (typeof secret !== 'string') {
      continue;
    }
    const updated = await Meteor.users.updateAsync(
      {
        _id: user._id,
        'services.twoFactorAuthentication.secret': secret,
      },
      {
        $set: { 'services.twoFactorAuthentication.secret': encryptSecret(secret) },
      }
    );
    migrated += typeof updated === 'number' ? updated : 0;
  }
  return migrated;
};

Accounts._check2faEnabled = user => {
  const { services: { twoFactorAuthentication } = {} } = user;
  return !!(
    twoFactorAuthentication &&
    twoFactorAuthentication.secret &&
    twoFactorAuthentication.type === 'otp'
  );
};

Accounts._is2faEnabledForUser = async () => {
  const user = await Meteor.userAsync();
  if (!user) {
    throw new Meteor.Error('no-logged-user', 'No user logged in.');
  }
  return Accounts._check2faEnabled(user);
};

Accounts._generate2faToken = (secret, timestamp = Date.now()) => ({
  token: getTotp({ secret: decryptSecret(secret) || secret }).generate({ timestamp }),
});

/**
 * @summary Validate a TOTP code and return the matching time step.
 * @locus Server
 * @param {String|Object} secret Plaintext secret, or a value sealed by oauth-encryption.
 * @param {String} code
 * @returns {Number|null}
 */
Accounts._verify2faToken = (secret, code) => {
  if (!Meteor.isServer) {
    throw new Meteor.Error(
      400,
      'The function _verify2faToken can only be called on the server'
    );
  }
  const plain = decryptSecret(secret);
  if (!plain || typeof code !== 'string') {
    return null;
  }
  const now = Date.now();
  try {
    const delta = getTotp({ secret: plain }).validate({
      token: code.replace(/\W+/g, ''),
      window: config.window,
      timestamp: now,
    });
    if (delta === null) {
      return null;
    }
    return Math.floor(now / 1000 / TOTP_PERIOD) + delta;
  } catch (error) {
    return null;
  }
};

Accounts._isTokenValid = (secret, code) =>
  Accounts._verify2faToken(secret, code) !== null;

/**
 * Atomically record a time step. Returns false when that step, or a later one, was already used.
 * `extraSelector` binds the write to the secret that was verified, so a concurrent
 * replacement of that secret is not activated.
 * @param {String} userId
 * @param {Number} step
 * @param {Object} [extraSet]
 * @param {Object} [extraSelector]
 * @returns {Promise<Boolean>}
 */
const consumeStep = async (userId, step, extraSet = {}, extraSelector = {}) => {
  const updated = await Meteor.users.updateAsync(
    {
      _id: userId,
      ...extraSelector,
      $or: [
        { 'services.twoFactorAuthentication.lastUsedStep': { $lt: step } },
        { 'services.twoFactorAuthentication.lastUsedStep': { $exists: false } },
      ],
    },
    {
      $set: {
        'services.twoFactorAuthentication.lastUsedStep': step,
        ...extraSet,
      },
    }
  );
  return updatedOne(updated);
};

const updatedOne = updated => (typeof updated === 'number' ? updated : 0) > 0;

const invalidCodeError = () =>
  Accounts._handleError('Invalid 2FA code', false, 'invalid-2fa-code');

const secretChangedError = () =>
  Accounts._handleError('2FA secret changed', false, '2fa-secret-changed');

/**
 * Run the code failure hooks, then return the invalid code error for the caller to throw.
 * @param {String} userId
 * @param {String} method
 * @returns {Promise<Error>}
 */
const reportInvalidCode = async (userId, method) => {
  await runHooks(codeFailureHooks, { userId, method });
  return invalidCodeError();
};

// A replayed login code is rejected here, after the password handler accepted it.
// Throwing sets attempt.error and the following validateLoginAttempt hooks still run.
Accounts.validateLoginAttempt(async attempt => {
  // A code rejected by the login handler itself never reaches the replay check below.
  if (attempt.error?.error === 'invalid-2fa-code' && attempt.user?._id) {
    await runHooks(codeFailureHooks, { userId: attempt.user._id, method: 'login' });
    return true;
  }
  if (!config.preventReplay || attempt.error || attempt.allowed === false) {
    return true;
  }
  if (!attempt.user || !config.loginTypes.includes(attempt.type)) {
    return true;
  }
  const code = attempt.methodArguments?.[0]?.code;
  if (typeof code !== 'string') {
    return true;
  }
  // attempt.user is loaded with defaultFieldSelector, which may omit services.
  const user = await Meteor.users.findOneAsync(attempt.user._id, {
    fields: { 'services.twoFactorAuthentication': 1 },
  });
  if (!user || !Accounts._check2faEnabled(user)) {
    return true;
  }
  const secret = user.services.twoFactorAuthentication.secret;
  const step = Accounts._verify2faToken(secret, code);
  if (step === null) {
    throw await reportInvalidCode(user._id, 'login');
  }
  const consumed = await consumeStep(user._id, step, {}, {
    'services.twoFactorAuthentication.secret': secret,
  });
  if (!consumed) {
    throw await reportInvalidCode(user._id, 'login');
  }
  return true;
});

Meteor.methods({
  async generate2faActivationQrCode(appName) {
    check(appName, String);
    const user = await Meteor.userAsync();

    if (!user) {
      throw new Meteor.Error(
        400,
        'There must be a user logged in to generate the QR code.'
      );
    }

    if (Accounts._check2faEnabled(user)) {
      throw new Meteor.Error(
        '2fa-activated',
        'The 2FA is activated. You need to disable the 2FA first before trying to generate a new activation code.'
      );
    }

    await runHooks(validateChangeHooks, {
      type: 'activation',
      stage: 'setup',
      user,
      connection: this.connection,
    });

    const emails = user.emails || [];
    const { secret, uri } = generateActivationData({
      issuer: appName.trim(),
      label: user.username || emails[0]?.address || user._id,
    });
    const svg = new QRCode(uri).svg();

    await Meteor.users.updateAsync(
      { _id: user._id },
      {
        $set: {
          'services.twoFactorAuthentication': {
            secret: encryptSecret(secret),
          },
        },
      }
    );

    return { svg, secret, uri };
  },
  async enableUser2fa(code) {
    check(code, String);
    const user = await Meteor.userAsync();

    if (!user) {
      throw new Meteor.Error(400, 'No user logged in.');
    }

    const twoFactorAuthentication = user.services?.twoFactorAuthentication;

    if (!twoFactorAuthentication?.secret) {
      throw new Meteor.Error(
        500,
        'The user does not have a secret generated. You may have to call the function generateSvgCode first.'
      );
    }

    await runHooks(validateChangeHooks, {
      type: 'activation',
      stage: 'confirm',
      user,
      connection: this.connection,
    });

    const step = Accounts._verify2faToken(twoFactorAuthentication.secret, code);
    if (step === null) {
      throw await reportInvalidCode(user._id, 'enableUser2fa');
    }

    const secretSelector = {
      'services.twoFactorAuthentication.secret': twoFactorAuthentication.secret,
    };
    const enabled = config.preventReplay
      ? await consumeStep(
        user._id,
        step,
        { 'services.twoFactorAuthentication.type': 'otp' },
        secretSelector
      )
      : updatedOne(await Meteor.users.updateAsync(
        { _id: user._id, ...secretSelector },
        { $set: { 'services.twoFactorAuthentication.type': 'otp' } }
      ));

    if (!enabled) {
      const current = await Meteor.users.findOneAsync(user._id, {
        fields: { 'services.twoFactorAuthentication.secret': 1 },
      });
      if (!EJSON.equals(current?.services?.twoFactorAuthentication?.secret, twoFactorAuthentication.secret)) {
        throw secretChangedError();
      }
      throw await reportInvalidCode(user._id, 'enableUser2fa');
    }

    await runHooks(changeHooks, {
      event: 'enabled',
      userId: user._id,
      connection: this.connection,
    });
  },
  async disableUser2fa() {
    const user = await Meteor.userAsync();
    const userId = user?._id;

    if (!userId) {
      throw new Meteor.Error(400, 'No user logged in.');
    }

    await runHooks(validateChangeHooks, {
      type: 'deactivation',
      user,
      connection: this.connection,
    });

    await Meteor.users.updateAsync(
      { _id: userId },
      {
        $unset: {
          'services.twoFactorAuthentication': 1,
        },
      }
    );
    await runHooks(changeHooks, {
      event: 'disabled',
      userId,
      connection: this.connection,
    });
  },
  async has2faEnabled() {
    return Accounts._is2faEnabledForUser();
  },
});

let rateLimitRuleId = null;
const applyRateLimit = () => {
  if (rateLimitRuleId) {
    DDPRateLimiter.removeRule(rateLimitRuleId);
  }
  rateLimitRuleId = DDPRateLimiter.addRule(
    {
      type: 'method',
      name: name => TWO_FACTOR_METHODS.includes(name),
      userId: () => true,
    },
    config.rateLimit.numRequests,
    config.rateLimit.timeInterval
  );
};

Meteor.startup(applyRateLimit);

Accounts.addAutopublishFields({
  forLoggedInUser: ['services.twoFactorAuthentication.type'],
});
