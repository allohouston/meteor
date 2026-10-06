import { Accounts } from 'meteor/accounts-base';
import * as OTPAuth from 'otpauth';
import { Random } from 'meteor/random';
import crypto from 'crypto';
import { OAuthEncryption } from 'meteor/oauth-encryption';

const restore2faConfig = () => {
  OAuthEncryption.loadKey(null);
  Accounts.configure2fa({
    window: 10,
    preventReplay: true,
    allowPlaintextSecrets: true,
  });
};

const findUserById =
  async id => await Meteor.users.findOneAsync(id);

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
    } finally {
      await Accounts.users.removeAsync(userId);
    }
  }
);
