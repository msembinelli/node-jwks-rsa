import debug from "debug";
import axios from "axios";

import ArgumentError from "./errors/ArgumentError";
import JwksError from "./errors/JwksError";
import SigningKeyNotFoundError from "./errors/SigningKeyNotFoundError";

import {
  certToPEM,
  rsaPublicKeyToPEM
} from "./utils";
import {
  cacheSigningKey,
  rateLimitSigningKey
} from "./wrappers";

export class JwksClient {
  constructor(options) {
    this.options = {
      rateLimit: false,
      cache: false,
      strictSsl: true,
      ...options
    };
    this.logger = debug("jwks");

    // Initialize wrappers.
    if (this.options.rateLimit) {
      this.getSigningKey = rateLimitSigningKey(this, options);
    }
    if (this.options.cache) {
      this.getSigningKey = cacheSigningKey(this, options);
    }
  }

  getKeys(cb) {
    this.logger(`Fetching keys from '${this.options.jwksUri}'`);
    axios
      .get(this.options.jwksUri, {
        json: true,
        url: this.options.jwksUri,
        strictSSL: this.options.strictSsl,
        headers: this.options.requestHeaders,
        agentOptions: this.options.requestAgentOptions
      })
      .then(response => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          this.logger("Failure:", response && response.data);
          return {
            err: new JwksError(
              (response.data && (response.data.message || response.data)) ||
              response.statusMessage ||
              `Http Error ${response.statusCode}`
            ),
            keys: null
          };
        }
        this.logger("Keys:", response.data.keys);
        return cb(null, response.data.keys)
      })
      .catch(error => {
        this.logger("Failure:", error);
        return cb(error);
      })
  }

  getSigningKeys(cb) {
    this.getKeys((err, keys) => {
      if (err) {
        return cb(err);
      }

      if (!keys || !keys.length) {
        return cb(new JwksError("The JWKS endpoint did not contain any keys"));
      }

      const signingKeys = keys
        .filter(key => {
          if (key.kty !== "RSA") {
            return false;
          }
          if (!key.kid) {
            return false;
          }
          if (key.hasOwnProperty("use") && key.use !== "sig") {
            return false;
          }
          return (key.x5c && key.x5c.length) || (key.n && key.e);
        })
        .map(key => {
          if (key.x5c && key.x5c.length) {
            return {
              kid: key.kid,
              nbf: key.nbf,
              publicKey: certToPEM(key.x5c[0])
            };
          } else {
            return {
              kid: key.kid,
              nbf: key.nbf,
              rsaPublicKey: rsaPublicKeyToPEM(key.n, key.e)
            };
          }
        });

      if (!signingKeys.length) {
        return cb(
          new JwksError("The JWKS endpoint did not contain any signing keys")
        );
      }

      this.logger("Signing Keys:", signingKeys);
      return cb(null, signingKeys);
    });
  }

  getSigningKey = (kid, cb) => {
    this.logger(`Fetching signing key for '${kid}'`);

    this.getSigningKeys((err, keys) => {
      if (err) {
        return cb(err);
      }

      const key = keys.find(k => k.kid === kid);
      if (key) {
        return cb(null, key);
      } else {
        this.logger(`Unable to find a signing key that matches '${kid}'`);
        return cb(
          new SigningKeyNotFoundError(
            `Unable to find a signing key that matches '${kid}'`
          )
        );
      }
    });
  };
}
