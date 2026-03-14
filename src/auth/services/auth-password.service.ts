import { Injectable } from '@nestjs/common';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { AuthPasswordServiceI } from '../interfaces/auth.utilities';

const SALT_BYTES = 16; // 128-bit salt
const KEY_LENGTH = 64; // 512-bit derived key
const scryptAsync = promisify(scrypt);
@Injectable()
export class AuthPasswordService implements AuthPasswordServiceI {
  public async hash(plain: string): Promise<string> {
    const salt = randomBytes(SALT_BYTES);

    const hash = (await scryptAsync(plain, salt, KEY_LENGTH)) as Buffer;
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
  }

  public async verify(plain: string, hash: string): Promise<boolean> {
    const [saltHex, hashHex] = hash.split(':');

    if (!saltHex || !hashHex) {
      return false; // malformed stored value — fail safely
    }

    const salt = Buffer.from(saltHex, 'hex');
    const storedHash = Buffer.from(hashHex, 'hex');
    const candidateHash = (await scryptAsync(
      plain,
      salt,
      KEY_LENGTH,
    )) as Buffer;

    // Buffers must be the same length before timingSafeEqual
    if (storedHash.length !== candidateHash.length) {
      return false;
    }

    return timingSafeEqual(storedHash, candidateHash);
  }
}
