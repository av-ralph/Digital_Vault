import { createHash, scrypt } from "node:crypto";
export const fingerprint = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export function passwordHash(password: string, salt: string) {
  return new Promise<Buffer>((resolve, reject) =>
    scrypt(
      password,
      salt,
      64,
      { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 },
      (err, key) => (err ? reject(err) : resolve(key)),
    ),
  );
}
