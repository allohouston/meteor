import { Accounts } from 'meteor/accounts-base';
import { DDP } from 'meteor/ddp-client';
import { DDPCommon } from 'meteor/ddp-common';
import * as OTPAuth from 'otpauth';
import { Random } from 'meteor/random';

const findUserById =
  async id => await Meteor.users.findOneAsync(id);

const restore2faConfig = () => {
  Accounts.configure2fa({
    window: 10,
    preventReplay: true,
    loginTypes: ['password', 'passwordless'],
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
