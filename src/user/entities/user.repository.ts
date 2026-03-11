import { UserEntity } from './user.entities';

export abstract class UserRepository {
  abstract findUser(username?: string, email?: string): Promise<UserEntity>;
  abstract updateUser(user: UserEntity): Promise<UserEntity>;
  abstract deleteUser(user: UserEntity): Promise<UserEntity>;
  abstract createUser(user: UserEntity): Promise<UserEntity>;
}
