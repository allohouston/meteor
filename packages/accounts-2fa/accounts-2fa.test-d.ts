import { expectTypeOf } from "expect-type";
import { Accounts } from "meteor/accounts-base";
import { Meteor } from "meteor/meteor";
import type {
  TwoFactorActivationData,
  TwoFactorChangeAttempt,
  TwoFactorChangeEvent,
  TwoFactorCodeFailure,
  TwoFactorConfigureOptions,
  TwoFactorEmailOptions,
  TwoFactorFactorEvent,
  TwoFactorStoredSecret,
} from "./accounts-2fa";

expectTypeOf<TwoFactorActivationData>().toEqualTypeOf<{
  svg: string;
  secret: string;
  uri: string;
}>();

expectTypeOf<TwoFactorConfigureOptions>().toEqualTypeOf<{
  window?: number;
  preventReplay?: boolean;
  loginTypes?: string[];
  rateLimit?: { numRequests: number; timeInterval: number };
  allowPlaintextSecrets?: boolean;
  requireCodeToDisable?: boolean;
  email?: TwoFactorEmailOptions;
}>();

Accounts.configure2fa({ requireCodeToDisable: true });
Accounts.disableUser2fa();
Accounts.disableUser2fa(() => {});
Accounts.disableUser2fa("123456", error => {
  expectTypeOf(error).toEqualTypeOf<Error | undefined>();
});

expectTypeOf<TwoFactorStoredSecret>().toEqualTypeOf<string | { [key: string]: unknown }>();
expectTypeOf(Accounts.encryptExisting2faSecrets()).toEqualTypeOf<Promise<number>>();
Accounts.configure2fa({ allowPlaintextSecrets: false });

Accounts.configure2fa({ rateLimit: { numRequests: 5, timeInterval: 60_000 } });

expectTypeOf<TwoFactorChangeEvent>().toEqualTypeOf<{
  event: "enabled" | "disabled" | "reset";
  userId: string;
  connection: Meteor.Connection | null;
}>();
expectTypeOf<TwoFactorCodeFailure>().toEqualTypeOf<{ userId: string; method: string }>();
expectTypeOf(Accounts.on2faChange(async ({ event }) => {
  expectTypeOf(event).toEqualTypeOf<"enabled" | "disabled" | "reset">();
}).stop).toEqualTypeOf<() => void>();
expectTypeOf(Accounts.on2faCodeFailure(({ userId }) => {
  expectTypeOf(userId).toBeString();
}).stop).toEqualTypeOf<() => void>();
expectTypeOf(Accounts.reset2faForUser("userId")).toEqualTypeOf<Promise<void>>();

// Example from the package guide.
Accounts.configure2fa({ window: 1 });
Accounts.configure2fa({ preventReplay: false, loginTypes: ["password", "custom"] });
expectTypeOf(Accounts.configure2fa).returns.toBeVoid();
// @ts-expect-error unknown option
Accounts.configure2fa({ windowSize: 1 });

expectTypeOf(Accounts._verify2faToken).returns.toEqualTypeOf<number | null>();
expectTypeOf(Accounts._generate2faToken("SECRET", Date.now())).toEqualTypeOf<{ token: string }>();

expectTypeOf<TwoFactorChangeAttempt>().toEqualTypeOf<{
  type: "activation" | "deactivation";
  stage?: "setup" | "confirm";
  user: Meteor.User;
  connection: Meteor.Connection | null;
}>();

expectTypeOf<TwoFactorEmailOptions>().toEqualTypeOf<{
  enabled?: boolean;
  offerToOtpUsers?: boolean;
  requireVerified?: boolean;
  expirationMs?: number;
  maxAttempts?: number;
  resendCooldownMs?: number;
  hashSecret?: string | null;
}>();
expectTypeOf<TwoFactorFactorEvent>().toEqualTypeOf<{
  user: Meteor.User;
  connection: Meteor.Connection | null;
  method: "otp" | "email";
}>();

// Example from the package guide.
Accounts.configure2fa({ email: { enabled: true, hashSecret: "server-secret" } });
expectTypeOf(Accounts.configure2fa).returns.toBeVoid();
// @ts-expect-error unknown email option
Accounts.configure2fa({ email: { enable: true } });

expectTypeOf(Accounts.on2faVerified(({ user, method }) => {
  expectTypeOf(user).toEqualTypeOf<Meteor.User>();
  expectTypeOf(method).toEqualTypeOf<"otp" | "email">();
}).stop).toEqualTypeOf<() => void>();
expectTypeOf(Accounts.validate2faChallenge(async ({ user }) => {
  if (!user._id) {
    throw new Meteor.Error("locked", "Account locked");
  }
}).stop).toEqualTypeOf<() => void>();

Accounts.set2faContextProvider(() => ({ trustedDeviceToken: "token" }));
Accounts.set2faContextProvider(() => null);
Accounts.request2faEmailCode("user@example.com", "password", error => {
  expectTypeOf(error).toEqualTypeOf<Error | Meteor.Error | undefined>();
});
Accounts.request2faEmailCode({ username: "user" }, "password");

const changeHandle = Accounts.validate2faChange(({ type, stage }) => {
  if (type === "activation" && stage === "setup") {
    throw new Meteor.Error("2fa-change-refused", "Enrollment is not available");
  }
});
expectTypeOf(changeHandle.stop).toEqualTypeOf<() => void>();
Accounts.validate2faChange(async () => {});

// Members this package augments onto Accounts (meteor/accounts-base).
expectTypeOf(Accounts.has2faEnabled).toBeFunction();
expectTypeOf(Accounts.generate2faActivationQrCode).toBeFunction();
expectTypeOf(Accounts.enableUser2fa).toBeFunction();
expectTypeOf(Accounts.disableUser2fa).toBeFunction();
expectTypeOf(Accounts.configure2fa).toBeFunction();
expectTypeOf(Accounts.validate2faChange).toBeFunction();
expectTypeOf(Accounts.on2faChange).toBeFunction();
expectTypeOf(Accounts.on2faCodeFailure).toBeFunction();
expectTypeOf(Accounts.reset2faForUser).toBeFunction();
expectTypeOf(Accounts.encryptExisting2faSecrets).toBeFunction();
expectTypeOf(Accounts.on2faVerified).toBeFunction();
expectTypeOf(Accounts.validate2faChallenge).toBeFunction();
expectTypeOf(Accounts.set2faContextProvider).toBeFunction();
expectTypeOf(Accounts.request2faEmailCode).toBeFunction();
expectTypeOf(Accounts._check2faEnabled).toBeFunction();
expectTypeOf(Accounts._is2faEnabledForUser).toBeFunction();
expectTypeOf(Accounts._generate2faToken).toBeFunction();
expectTypeOf(Accounts._verify2faToken).toBeFunction();
expectTypeOf(Accounts._isTokenValid).toBeFunction();
