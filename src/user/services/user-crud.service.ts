import { Injectable } from '@nestjs/common';
import { UserEntity } from '../interfaces/user.entities';
import { UserCRUDI } from '../interfaces/user.utilities';
import { UserDBService } from './user-db.service';

@Injectable()
export class UserCRUDService implements UserCRUDI {
  constructor(private readonly userDBService: UserDBService) {}

  createUser(username: string, email: string, password: string): Promise<UserEntity> {
    return this.userDBService.createUser(username, email, password);
  }

  deleteUser(email: string): Promise<UserEntity> {
    return this.userDBService.deleteUser(email);
  }

  updateUser(username: string, email: string, password: string): Promise<UserEntity> {
    return this.userDBService.updateUser(username, email, password);
  }
  findByUsernameOrEmail(
    username?: string,
    email?: string,
  ): Promise<UserEntity | null> {
    return this.userDBService.findByUsernameOrEmail(username, email);
  }
  findById(id: string): Promise<UserEntity | null> {
    return this.userDBService.findById(id);
  }
}
