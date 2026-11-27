import { SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, AuthResult } from './types';
import { parsePrivateKey } from './openssh-key';
import { encodeString, concat, readUint32 } from './utils';

export class SSHAuth {
  static buildPasswordAuthRequest(
    username: string,
    password: string
  ): Uint8Array {
    const parts: Uint8Array[] = [
      new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
      encodeString(username),
      encodeString('ssh-connection'),
      encodeString('password'),
      new Uint8Array([0x00]),
      encodeString(password),
    ];

    return concat(...parts);
  }

  /**
   * Build a public key auth request (RFC 4252 §7 / RFC 8332).
   * Supports OpenSSH and PEM private keys: Ed25519, RSA (rsa-sha2-512), ECDSA.
   */
  static async buildPublicKeyAuthRequest(
    username: string,
    privateKeyPEM: string,
    sessionID: Uint8Array,
    passphrase?: string,
  ): Promise<Uint8Array> {
    const key = await parsePrivateKey(privateKeyPEM, passphrase);

    const requestBody = concat(
      new Uint8Array([SSH_MSG_USERAUTH_REQUEST]),
      encodeString(username),
      encodeString('ssh-connection'),
      encodeString('publickey'),
      new Uint8Array([0x01]),
      encodeString(key.algorithm),
      encodeString(key.publicKeyBlob),
    );

    const dataToSign = concat(encodeString(sessionID), requestBody);
    const signatureBlob = await key.sign(dataToSign);

    return concat(requestBody, encodeString(signatureBlob));
  }

  static handleResponse(payload: Uint8Array): AuthResult {
    const msgType = payload[0];

    switch (msgType) {
      case SSH_MSG_USERAUTH_SUCCESS:
        return { success: true };

      case SSH_MSG_USERAUTH_FAILURE: {
        const len = readUint32(payload, 1);
        const methods = new TextDecoder().decode(
          payload.slice(5, 5 + len)
        );
        const partialSuccess =
          payload.length > 5 + len ? payload[5 + len] !== 0 : false;
        return {
          success: false,
          allowedMethods: methods.split(',').filter(Boolean),
          partialSuccess,
        };
      }

      default:
        throw new Error(`Unexpected auth message type: ${msgType}`);
    }
  }
}
