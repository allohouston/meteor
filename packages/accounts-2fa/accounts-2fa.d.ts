import { Meteor } from 'meteor/meteor';

export interface TwoFactorActivationData {
  svg: string;
  secret: string;
  uri: string;
}

/** Options accepted by `Accounts.configure2fa`. */
export interface TwoFactorConfigureOptions {
  /** TOTP steps accepted on each side of the current step (default 10). */
  window?: number;
  /** Reject a step at or before the last accepted one (default true). */
  preventReplay?: boolean;
  /** Login attempt types that get replay protection. Replaces the default `['password', 'passwordless']`. */
  loginTypes?: string[];
  /** Per-user limit for the 2FA methods (default 5 calls per 60 000 ms). Setting it again replaces the rule. */
  rateLimit?: { numRequests: number; timeInterval: number };
  /** Accept secrets stored before encryption was enabled (default true). */
  allowPlaintextSecrets?: boolean;
  /** Require a current TOTP code to disable an active authenticator (default false). */
  requireCodeToDisable?: boolean;
  /** Email second factor. Disabled until `email.enabled` is true. */
  email?: TwoFactorEmailOptions;
}

/** Payload passed to `Accounts.on2faChange` callbacks. */
export interface TwoFactorChangeEvent {
  event: 'enabled' | 'disabled' | 'reset';
  userId: string;
  connection: Meteor.Connection | null;
}

/** Payload passed to `Accounts.on2faCodeFailure` callbacks. */
export interface TwoFactorCodeFailure {
  userId: string;
  /** `login`, or the name of the 2FA method that rejected the code. */
  method: string;
}

/**
 * Payload passed to `Accounts.validate2faChange` callbacks.
 * `stage` is only set for an activation: `setup` when a secret is about to be
 * issued, `confirm` when 2FA is about to be turned on.
 */
export interface TwoFactorChangeAttempt {
  type: 'activation' | 'deactivation';
  stage?: 'setup' | 'confirm';
  /** Same shape as `Meteor.user()`, so it respects `defaultFieldSelector`. */
  user: Meteor.User;
  connection: Meteor.Connection | null;
}

/** A stored TOTP secret: plaintext, or a value sealed by `oauth-encryption`. */
export type TwoFactorStoredSecret = string | { [key: string]: unknown };

/** Email second factor options. Disabled until `enabled` is true. */
export interface TwoFactorEmailOptions {
  enabled?: boolean;
  /** Let a user who already has TOTP choose email (default false). */
  offerToOtpUsers?: boolean;
  /** Send codes only to a verified address (default true). */
  requireVerified?: boolean;
  /** Code lifetime in milliseconds (default 600 000). */
  expirationMs?: number;
  /** Wrong codes accepted before the code is discarded (default 5). */
  maxAttempts?: number;
  /** Minimum delay between two sends, in milliseconds (default 60 000). */
  resendCooldownMs?: number;
  /** Server secret for the email-code HMAC. Without it, codes are hashed with SHA-256 and a warning is logged. */
  hashSecret?: string | null;
}

/** Payload passed to `Accounts.on2faVerified` and `Accounts.validate2faChallenge` callbacks. */
export interface TwoFactorFactorEvent {
  user: Meteor.User;
  connection: Meteor.Connection | null;
  method: 'otp' | 'email';
}

declare module 'meteor/accounts-base' {
  namespace Accounts {
    /**
     * Check whether the logged-in user has 2FA enabled.
     * The callback receives a boolean on success, or a single Error on failure.
     */
    function has2faEnabled(callback: (error: Error | undefined, enabled?: boolean) => void): void;

    /**
     * Generate an activation QR code (SVG) plus secret and URI for setting up 2FA.
     * @param appName Application name shown inside the authenticator app.
     */
    function generate2faActivationQrCode(
      appName: string,
      callback: (error: Error | undefined, data?: TwoFactorActivationData) => void
    ): void;

    /**
     * Enable 2FA for the logged-in user using a code from the authenticator.
     */
    function enableUser2fa(code: string, callback?: (error?: Error) => void): void;

    /**
     * Disable 2FA for the logged-in user.
     * Pass a current code when the server sets `requireCodeToDisable`.
     */
    function disableUser2fa(callback?: (error?: Error) => void): void;
    function disableUser2fa(code: string, callback?: (error?: Error) => void): void;

    /** Configure TOTP verification and replay protection (server only). */
    function configure2fa(options: TwoFactorConfigureOptions): void;

    /**
     * Refuse a 2FA activation or deactivation (server only).
     * Throw a `Meteor.Error` from the callback to refuse the change and report
     * the reason to the user. Any other exception reaches the client as a 500.
     */
    function validate2faChange(
      callback: (attempt: TwoFactorChangeAttempt) => void | Promise<void>
    ): { stop: () => void };

    /** Called after 2FA is enabled, disabled or reset (server only). */
    function on2faChange(
      callback: (event: TwoFactorChangeEvent) => void | Promise<void>
    ): { stop: () => void };

    /** Called when a 2FA code is rejected (server only). */
    function on2faCodeFailure(
      callback: (failure: TwoFactorCodeFailure) => void | Promise<void>
    ): { stop: () => void };

    /**
     * Remove 2FA from a user without a code (server only).
     * Not a method and no permission check: the app decides who may call it.
     */
    function reset2faForUser(
      userId: string,
      options?: { connection?: Meteor.Connection | null }
    ): Promise<void>;

    /**
     * Seal the TOTP secrets still stored in plaintext (server only).
     * Requires `oauth-encryption` with a loaded `oauthSecretKey`. Resolves to the number of users migrated.
     */
    function encryptExisting2faSecrets(): Promise<number>;

    /**
     * Called after a login that presented a second factor was allowed (server only).
     * A thrown error is logged and ignored.
     */
    function on2faVerified(
      callback: (event: TwoFactorFactorEvent) => void | Promise<void>
    ): { stop: () => void };

    /**
     * Called before an email code is sent (server only).
     * Throw to skip the send. The login fails with that error.
     */
    function validate2faChallenge(
      callback: (event: TwoFactorFactorEvent) => void | Promise<void>
    ): { stop: () => void };

    /**
     * Provide string data sent with every login, such as a trusted-browser token (client only).
     */
    function set2faContextProvider(
      provider: () => Record<string, string> | null | undefined
    ): void;

    /**
     * Ask the server to email a second-factor code after checking the password (client only).
     * The callback receives the `no-2fa-code` error when the message was sent or is on cooldown.
     */
    function request2faEmailCode(
      selector: string | { username: string } | { email: string } | { id: string },
      password: string,
      callback?: (error?: Error | Meteor.Error) => void
    ): void;

    /** Returns true if the user document has an active `services.twoFactorAuthentication`. */
    function _check2faEnabled(user: Meteor.User): boolean;

    /** Server-side check against the currently logged-in user. */
    function _is2faEnabledForUser(): Promise<boolean>;

    /** Generate an OTP token for the given secret, at `timestamp` (ms) when given. */
    function _generate2faToken(secret: TwoFactorStoredSecret, timestamp?: number): { token: string };

    /** Verify an OTP code and return its time step, or null when invalid (server only). */
    function _verify2faToken(secret: TwoFactorStoredSecret, code: string): number | null;

    /** Verify an OTP code against a secret (server only). */
    function _isTokenValid(secret: TwoFactorStoredSecret, code: string): boolean;
  }
}

export {};
