import { Accounts } from 'meteor/accounts-base';
import { DDP } from 'meteor/ddp-client';
import { DDPCommon } from 'meteor/ddp-common';
import { DDPRateLimiter } from 'meteor/ddp-rate-limiter';
import * as OTPAuth from 'otpauth';
import { Random } from 'meteor/random';
import crypto from 'crypto';
import { OAuthEncryption } from 'meteor/oauth-encryption';

const findUserById =
  async id => await Meteor.users.findOneAsync(id);

const restore2faConfig = () => {
  OAuthEncryption.loadKey(null);
  Accounts.configure2fa({
    window: 10,
    preventReplay: true,
    loginTypes: ['password', 'passwordless'],
    allowPlaintextSecrets: true,
    requireCodeToDisable: false,
  });
};

const insertUser = async (fields = {}) =>
  Accounts.insertUserDoc(
    {},
    {
      emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
      ...fields,
    }
  );

const callAs = (userId, name, ...args) => {
  const method = Meteor.server.method_handlers[name];
  const invocation = new DDPCommon.MethodInvocation({
    userId,
    isSimulation: false,
    setUserId: () => {},
    unblock: () => {},
    connection: { id: 'conn', close() {} },
    randomSeed: Random.id(),
  });
  return DDP._CurrentMethodInvocation.withValue(invocation, () =>
    method.apply(invocation, args)
  );
};

const callAsUser = (userId, name, args) => callAs(userId, name, ...args);

const refuseChange = () =>
  Accounts.validate2faChange(() => {
    throw new Meteor.Error('2fa-change-refused', 'change refused');
  });

const loginWithCode = (userId, code, type = 'password') =>
  Accounts._attemptLogin(
    {
      connection: { id: Random.id(), close() {} },
      setUserId() {},
    },
    'login',
    [{ user: { id: userId }, code }],
    { userId, type }
  );

const insertOtpUser = (secret, twoFactorAuthentication) =>
  Accounts.insertUserDoc(
    {},
    {
      emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
      services: {
        twoFactorAuthentication: twoFactorAuthentication || { type: 'otp', secret },
      },
    }
  );

const enableUser2fa = (userId, code) =>
  DDP._CurrentMethodInvocation.withValue(
    { userId },
    () => Meteor.server.method_handlers.enableUser2fa.apply({ userId }, [code])
  );

Tinytest.addAsync('account - 2fa - has2faEnabled - server', async test => {
  // Create users
  const userWithout2FA = await Accounts.insertUserDoc(
    {},
    { emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }] }
  );
  const userWith2FA = await Accounts.insertUserDoc(
    {},
    {
      emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
      services: {
        twoFactorAuthentication: { type: 'otp', secret: 'superSecret' },
      },
    }
  );

  test.equal(Accounts._check2faEnabled(await findUserById(userWithout2FA)), false);
  test.equal(Accounts._check2faEnabled(await findUserById(userWith2FA)), true);

  // cleanup
  await Accounts.users.removeAsync(userWithout2FA);
  await Accounts.users.removeAsync(userWith2FA);
});

Tinytest.add('account - 2fa - generated tokens validate against Base32 secrets', test => {
  const secret = new OTPAuth.Secret({ size: 20 }).base32;
  const { token } = Accounts._generate2faToken(secret);

  test.equal(token.length, 6);
  test.isTrue(/^[A-Z2-7]+$/.test(secret));
  test.isTrue(Accounts._isTokenValid(secret, token));
  test.isFalse(Accounts._isTokenValid(secret, '000000'));
});

Tinytest.add('account - 2fa - existing lowercase secrets remain valid', test => {
  const secret = 'jbswy3dpehpk3pxp';
  const { token } = Accounts._generate2faToken(secret);

  test.isTrue(Accounts._isTokenValid(secret, token));
});

Tinytest.addAsync(
  'account - 2fa - sealed secrets still validate and plaintext can be rejected',
  async test => {
    const key = crypto.randomBytes(16).toString('base64');
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await Accounts.insertUserDoc(
      {},
      {
        emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
        services: {
          twoFactorAuthentication: { type: 'otp', secret },
        },
      }
    );

    try {
      OAuthEncryption.loadKey(key);
      Accounts.configure2fa({ allowPlaintextSecrets: false });

      test.equal(await Accounts.encryptExisting2faSecrets(), 1);
      const user = await findUserById(userId);
      const stored = user.services.twoFactorAuthentication.secret;
      test.isTrue(OAuthEncryption.isSealed(stored));

      const { token } = Accounts._generate2faToken(stored);
      test.isTrue(Accounts._isTokenValid(stored, token));
      test.isFalse(Accounts._isTokenValid(secret, token));

      OAuthEncryption.loadKey(crypto.randomBytes(16).toString('base64'));
      test.isFalse(Accounts._isTokenValid(stored, token));
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - a replayed activation code on a sealed secret is an invalid code',
  async test => {
    OAuthEncryption.loadKey(crypto.randomBytes(16).toString('base64'));
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const sealed = OAuthEncryption.seal(secret);
    const userId = await insertOtpUser(sealed, {
      secret: sealed,
      lastUsedStep: Math.floor(Date.now() / 30_000) + 1,
    });
    const { token } = Accounts._generate2faToken(secret);

    try {
      let error = null;
      try {
        await enableUser2fa(userId, token);
      } catch (caught) {
        error = caught;
      }
      test.equal(error && error.error, 'invalid-2fa-code');
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - a login code cannot be replayed',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await Accounts.insertUserDoc(
      {},
      {
        emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
        services: {
          twoFactorAuthentication: { type: 'otp', secret },
        },
      }
    );
    const { token } = Accounts._generate2faToken(secret);
    const invocation = {
      connection: {
        id: Random.id(),
        close() {},
      },
      setUserId() {},
    };
    const attempt = () =>
      Accounts._attemptLogin(
        invocation,
        'login',
        [{ user: { id: userId }, code: token }],
        { userId, type: 'password' }
      );

    try {
      const first = await attempt();
      test.equal(first.id, userId);

      let replayError = null;
      try {
        await attempt();
      } catch (error) {
        replayError = error;
      }
      test.equal(replayError && replayError.error, 'invalid-2fa-code');

      const next = Accounts._generate2faToken(secret, Date.now() + 30_000).token;
      const nextLogin = await Accounts._attemptLogin(
        invocation,
        'login',
        [{ user: { id: userId }, code: next }],
        { userId, type: 'password' }
      );
      test.equal(nextLogin.id, userId);
    } finally {
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - only one of two simultaneous logins accepts a code',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret);
    const { token } = Accounts._generate2faToken(secret);

    try {
      const results = await Promise.allSettled([
        loginWithCode(userId, token),
        loginWithCode(userId, token),
      ]);
      const fulfilled = results.filter(result => result.status === 'fulfilled');
      const rejected = results.filter(result => result.status === 'rejected');
      test.equal(fulfilled.length, 1);
      test.equal(fulfilled[0].value.id, userId);
      test.equal(rejected.length, 1);
      test.equal(rejected[0].reason.error, 'invalid-2fa-code');
    } finally {
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - activation consumes the step',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret, { secret });
    const { token } = Accounts._generate2faToken(secret);

    try {
      await enableUser2fa(userId, token);
      test.isTrue(Accounts._check2faEnabled(await findUserById(userId)));

      let replayError = null;
      try {
        await loginWithCode(userId, token);
      } catch (error) {
        replayError = error;
      }
      test.equal(replayError && replayError.error, 'invalid-2fa-code');
    } finally {
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - an older step is rejected after a newer one',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret);
    const now = Date.now();
    const newer = Accounts._generate2faToken(secret, now + 30_000).token;
    const older = Accounts._generate2faToken(secret, now).token;

    try {
      const first = await loginWithCode(userId, newer);
      test.equal(first.id, userId);

      let replayError = null;
      try {
        await loginWithCode(userId, older);
      } catch (error) {
        replayError = error;
      }
      test.equal(replayError && replayError.error, 'invalid-2fa-code');
    } finally {
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - preventReplay false allows reuse',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret);
    const { token } = Accounts._generate2faToken(secret);
    Accounts.configure2fa({ preventReplay: false });

    try {
      const first = await loginWithCode(userId, token);
      const second = await loginWithCode(userId, token);
      test.equal(first.id, userId);
      test.equal(second.id, userId);
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.add(
  'account - 2fa - configure2fa rejects a negative window',
  test => {
    let error = null;
    try {
      Accounts.configure2fa({ window: -1 });
    } catch (caught) {
      error = caught;
    }
    test.isTrue(!!error && error.message.includes('window must be >= 0'));

    try {
      Accounts.configure2fa({ window: 1 });
      const secret = new OTPAuth.Secret({ size: 20 }).base32;
      const now = Date.now();
      const inside = Accounts._generate2faToken(secret, now + 30_000).token;
      const outside = Accounts._generate2faToken(secret, now + 90_000).token;
      test.isTrue(Accounts._isTokenValid(secret, inside));
      test.isFalse(Accounts._isTokenValid(secret, outside));
    } finally {
      restore2faConfig();
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - replay protection ignores a positive defaultFieldSelector',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret);
    const { token } = Accounts._generate2faToken(secret);
    const previous = Accounts._options.defaultFieldSelector;
    delete Accounts._options.defaultFieldSelector;
    Accounts.config({ defaultFieldSelector: { username: 1 } });

    try {
      const first = await loginWithCode(userId, token);
      test.equal(first.id, userId);

      let replayError = null;
      try {
        await loginWithCode(userId, token);
      } catch (error) {
        replayError = error;
      }
      test.equal(replayError && replayError.error, 'invalid-2fa-code');
    } finally {
      delete Accounts._options.defaultFieldSelector;
      if (previous !== undefined) {
        Accounts._options.defaultFieldSelector = previous;
      }
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - a login type outside loginTypes does not consume the step',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret);
    const { token } = Accounts._generate2faToken(secret);
    Accounts.configure2fa({ loginTypes: ['password'] });

    try {
      const first = await loginWithCode(userId, token, 'custom');
      const second = await loginWithCode(userId, token, 'custom');
      const passwordLogin = await loginWithCode(userId, token);
      test.equal(first.id, userId);
      test.equal(second.id, userId);
      test.equal(passwordLogin.id, userId);
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync('account - 2fa - validate2faChange can refuse an activation', async test => {
  const guard = refuseChange();
  try {
    const userId = await insertUser();
    try {
      await callAs(userId, 'generate2faActivationQrCode', 'Test app');
      test.fail('the activation should have been refused');
    } catch (error) {
      test.equal(error.error, '2fa-change-refused');
    }
    const user = await findUserById(userId);
    test.isFalse(!!user.services?.twoFactorAuthentication?.secret);
  } finally {
    guard.stop();
  }
});

Tinytest.addAsync('account - 2fa - validate2faChange can refuse enabling 2FA', async test => {
  const guard = refuseChange();
  const secret = new OTPAuth.Secret({ size: 20 }).base32;
  try {
    const userId = await insertUser({
      services: { twoFactorAuthentication: { secret } },
    });
    const { token } = Accounts._generate2faToken(secret);
    try {
      await callAs(userId, 'enableUser2fa', token);
      test.fail('enabling 2FA should have been refused');
    } catch (error) {
      test.equal(error.error, '2fa-change-refused');
    }
    const user = await findUserById(userId);
    test.equal(user.services.twoFactorAuthentication.secret, secret);
    test.isFalse(!!user.services.twoFactorAuthentication.type);
  } finally {
    guard.stop();
  }
});

Tinytest.addAsync('account - 2fa - validate2faChange can refuse disabling 2FA', async test => {
  const guard = refuseChange();
  const secret = 'jbswy3dpehpk3pxp';
  try {
    const userId = await insertUser({
      services: { twoFactorAuthentication: { type: 'otp', secret } },
    });
    try {
      await callAs(userId, 'disableUser2fa');
      test.fail('disabling 2FA should have been refused');
    } catch (error) {
      test.equal(error.error, '2fa-change-refused');
    }
    const user = await findUserById(userId);
    test.equal(user.services.twoFactorAuthentication.secret, secret);
  } finally {
    guard.stop();
  }
});

Tinytest.addAsync('account - 2fa - validate2faChange stop lets the same call succeed', async test => {
  const guard = refuseChange();
  try {
    const userId = await insertUser();
    try {
      await callAs(userId, 'generate2faActivationQrCode', 'Test app');
      test.fail('the activation should have been refused');
    } catch (error) {
      test.equal(error.error, '2fa-change-refused');
    }
    guard.stop();
    const { secret } = await callAs(userId, 'generate2faActivationQrCode', 'Test app');
    const user = await findUserById(userId);
    test.equal(user.services.twoFactorAuthentication.secret, secret);
  } finally {
    guard.stop();
  }
});

Tinytest.addAsync('account - 2fa - validate2faChange receives the change payload', async test => {
  const seen = [];
  const guard = Accounts.validate2faChange(payload => {
    seen.push(payload);
  });
  const userId = await insertUser();
  try {
    const { secret } = await callAs(userId, 'generate2faActivationQrCode', 'Test app');
    const { token } = Accounts._generate2faToken(secret);
    await callAs(userId, 'enableUser2fa', token);
    await callAs(userId, 'disableUser2fa');
  } finally {
    guard.stop();
  }
  test.equal(seen.map(({ type, stage }) => ({ type, stage })), [
    { type: 'activation', stage: 'setup' },
    { type: 'activation', stage: 'confirm' },
    { type: 'deactivation', stage: undefined },
  ]);
  seen.forEach(payload => {
    test.equal(payload.user._id, userId);
    test.equal(payload.connection.id, 'conn');
  });
});

Tinytest.addAsync('account - 2fa - reset2faForUser clears 2FA and notifies hooks', async test => {
  const userId = await Accounts.insertUserDoc(
    {},
    {
      emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
      services: {
        twoFactorAuthentication: { type: 'otp', secret: 'superSecret' },
      },
    }
  );
  let event = null;
  const hook = Accounts.on2faChange(payload => {
    event = payload;
  });

  try {
    await Accounts.reset2faForUser(userId, { connection: { id: 'conn' } });
    const user = await findUserById(userId);
    test.isFalse(Accounts._check2faEnabled(user));
    test.equal(event && event.event, 'reset');
    test.equal(event && event.userId, userId);
  } finally {
    hook.stop();
    await Accounts.users.removeAsync(userId);
  }
});

Tinytest.addAsync('account - 2fa - a rejected code notifies on2faCodeFailure', async test => {
  const secret = new OTPAuth.Secret({ size: 20 }).base32;
  const userId = await Accounts.insertUserDoc(
    {},
    {
      emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
      services: {
        twoFactorAuthentication: { type: 'otp', secret },
      },
    }
  );
  let failure = null;
  const hook = Accounts.on2faCodeFailure(payload => {
    failure = payload;
  });
  const invocation = {
    connection: { id: Random.id(), close() {} },
    setUserId() {},
  };

  try {
    await Accounts._attemptLogin(
      invocation,
      'login',
      [{ user: { id: userId }, code: '000000' }],
      { userId, type: 'password' }
    );
    test.fail('the code should have been rejected');
  } catch (error) {
    test.equal(error.error, 'invalid-2fa-code');
    test.equal(failure && failure.userId, userId);
    test.equal(failure && failure.method, 'login');
  } finally {
    hook.stop();
    await Accounts.users.removeAsync(userId);
  }
});

Tinytest.addAsync('account - 2fa - a code rejected by the login handler notifies on2faCodeFailure', async test => {
  const userId = await Accounts.insertUserDoc(
    {},
    { emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }] }
  );
  let failure = null;
  const hook = Accounts.on2faCodeFailure(payload => {
    failure = payload;
  });
  const invocation = {
    connection: { id: Random.id(), close() {} },
    setUserId() {},
  };

  try {
    await Accounts._attemptLogin(invocation, 'login', [{}], {
      userId,
      type: 'password',
      error: Accounts._handleError('Invalid 2FA code', false, 'invalid-2fa-code'),
    });
    test.fail('the login should have been rejected');
  } catch (error) {
    test.equal(error.error, 'invalid-2fa-code');
    test.equal(failure, { userId, method: 'login' });
  } finally {
    hook.stop();
    await Accounts.users.removeAsync(userId);
  }
});

Tinytest.addAsync('account - 2fa - configure2fa replaces the rate limit after startup', async test => {
  const beforeIds = new Set(Object.keys(DDPRateLimiter.printRules()));
  Accounts.configure2fa({
    rateLimit: { numRequests: 7, timeInterval: 12345 },
  });
  const after = DDPRateLimiter.printRules();
  const added = Object.keys(after).filter(id => !beforeIds.has(id));

  try {
    test.equal(added.length, 1);
    test.equal(after[added[0]].options.numRequestsAllowed, 7);
    test.equal(after[added[0]].options.intervalTime, 12345);
  } finally {
    Accounts.configure2fa({
      rateLimit: { numRequests: 5, timeInterval: 60_000 },
    });
  }
});

Tinytest.addAsync(
  'account - 2fa - disabling 2FA requires a current code when configured',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await Accounts.insertUserDoc(
      {},
      {
        emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
        services: {
          twoFactorAuthentication: { type: 'otp', secret },
        },
      }
    );
    const { token } = Accounts._generate2faToken(secret);

    try {
      Accounts.configure2fa({ requireCodeToDisable: true });
      let refused = null;
      try {
        await callAsUser(userId, 'disableUser2fa', []);
      } catch (error) {
        refused = error;
      }
      test.equal(refused && refused.error, 'invalid-2fa-code');
      test.isTrue(Accounts._check2faEnabled(await findUserById(userId)));

      await callAsUser(userId, 'disableUser2fa', [token]);
      test.isFalse(Accounts._check2faEnabled(await findUserById(userId)));
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - requireCodeToDisable ignores a positive defaultFieldSelector',
  async test => {
    const secret = new OTPAuth.Secret({ size: 20 }).base32;
    const userId = await insertOtpUser(secret);
    const previous = Accounts._options.defaultFieldSelector;
    delete Accounts._options.defaultFieldSelector;
    Accounts.config({ defaultFieldSelector: { username: 1 } });

    try {
      Accounts.configure2fa({ requireCodeToDisable: true });
      let refused = null;
      try {
        await callAsUser(userId, 'disableUser2fa', []);
      } catch (error) {
        refused = error;
      }
      test.equal(refused && refused.error, 'invalid-2fa-code');
      test.isTrue(Accounts._check2faEnabled(await findUserById(userId)));
    } finally {
      delete Accounts._options.defaultFieldSelector;
      if (previous !== undefined) {
        Accounts._options.defaultFieldSelector = previous;
      }
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - a secret that was never activated can be discarded without a code',
  async test => {
    const userId = await Accounts.insertUserDoc(
      {},
      { emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }] }
    );

    try {
      Accounts.configure2fa({ requireCodeToDisable: true });
      await callAsUser(userId, 'generate2faActivationQrCode', ['Test app']);
      const pending = await findUserById(userId);
      test.isTrue(!!pending.services?.twoFactorAuthentication?.secret);
      test.isFalse(Accounts._check2faEnabled(pending));

      await callAsUser(userId, 'disableUser2fa', []);
      const user = await findUserById(userId);
      test.isFalse(!!user.services?.twoFactorAuthentication);
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);

Tinytest.addAsync(
  'account - 2fa - requireCodeToDisable false keeps disable without a code',
  async test => {
    const userId = await Accounts.insertUserDoc(
      {},
      {
        emails: [{ address: `${Random.id()}@meteorapp.com`, verified: true }],
        services: {
          twoFactorAuthentication: { type: 'otp', secret: 'superSecret' },
        },
      }
    );

    try {
      Accounts.configure2fa({ requireCodeToDisable: false });
      await callAsUser(userId, 'disableUser2fa', []);
      test.isFalse(Accounts._check2faEnabled(await findUserById(userId)));
    } finally {
      restore2faConfig();
      await Accounts.users.removeAsync(userId);
    }
  }
);
