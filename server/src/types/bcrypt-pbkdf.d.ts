declare module "bcrypt-pbkdf" {
  export function pbkdf(
    pass: Uint8Array,
    passlen: number,
    salt: Uint8Array,
    saltlen: number,
    key: Uint8Array,
    keylen: number,
    rounds: number,
  ): number;

  const bcryptPbkdf: {
    pbkdf: typeof pbkdf;
  };

  export default bcryptPbkdf;
}
