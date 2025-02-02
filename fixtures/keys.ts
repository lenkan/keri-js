import { decodeBase64 } from "../src/parser/base64.ts";

export const privateKey00 = decodeBase64("vEf7c50OqZJQLOjns/3B8k5Q/PQeh9smuZgiQXU7heU=");
export const privateKey11 = decodeBase64("Ky3v2P+1/6yGB1ZI4o8vk/Zi629oa64ks88X02i9vag=");

// const salt = "0ACDEyMzQ1Njc4OWxtbm9aBc";
// function generateSaltyKey(args: { salt: string; password: string }) {
//   const opslimit = 2;
//   const memlimit = 67108864;
//   const salt = cesr.decode(args.salt);

//   return libsodium.crypto_pwhash(
//     32,
//     args.password ?? "",
//     salt.buffer,
//     opslimit,
//     memlimit,
//     libsodium.crypto_pwhash_ALG_ARGON2ID13,
//   );
// }

//   const privateKey00 = generateSaltyKey({ salt, password: "alice00" });
//   const privateKey01 = generateSaltyKey({ salt, password: "alice11" });
