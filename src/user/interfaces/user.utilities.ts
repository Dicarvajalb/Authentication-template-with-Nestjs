import { UserEntity } from './user.entities';

export interface UserDBI {
  findByUsernameOrEmail(username?: string, email?: string): Promise<UserEntity | null>;
  updateUser(username: string, email: string, password: string): Promise<UserEntity>;
  deleteUser(email: string): Promise<UserEntity>;
  createUser(username: string, email: string, password: string): Promise<UserEntity>;
  findById(id: string): Promise<UserEntity | null>;
}

export interface UserCRUDI {
  findByUsernameOrEmail(username?: string, email?: string): Promise<UserEntity | null>;
  updateUser(username: string, email: string, password: string): Promise<UserEntity>;
  deleteUser(email: string): Promise<UserEntity>;
  createUser(username: string, email:  string, password: string): Promise<UserEntity>;
  findById(id: string): Promise<UserEntity | null>;
}
