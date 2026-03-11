import { UserEntity } from '../entities/user.entities';
import { UserRepository } from '../entities/user.repository';

export type CreateUserI = {
  email: string;
  username: string;
  password: string;
};
export class CreateUserUS {
  constructor(private readonly userRepository: UserRepository) {}

  public execute(input: CreateUserI): UserEntity {
    return this.userRepository.createUser({
      email: input.email,
      password: input.password,
      username: input.username,
    });
  }
}
