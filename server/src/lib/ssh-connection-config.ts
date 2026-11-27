import { parsePrivateKeyCredential } from "../lib/private-key-credential";
import type { ServerRecord } from "../types";
import type { SSHConnectionConfig } from "../ssh/types";

export function buildSSHConnectionConfig(
  serverRecord: ServerRecord,
  credential: string,
): SSHConnectionConfig {
  if (serverRecord.auth_type === "password") {
    return {
      host: serverRecord.host,
      port: serverRecord.port,
      username: serverRecord.username,
      password: credential,
      authMethod: "password",
      cols: 120,
      rows: 40,
    };
  }

  const parsed = parsePrivateKeyCredential(credential);
  return {
    host: serverRecord.host,
    port: serverRecord.port,
    username: serverRecord.username,
    password: "",
    authMethod: "publickey",
    privateKey: parsed.privateKey,
    privateKeyPassphrase: parsed.passphrase,
    cols: 120,
    rows: 40,
  };
}
