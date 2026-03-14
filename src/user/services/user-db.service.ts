import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserEntity } from '../interfaces/user.entities';
import { UserDBI } from '../interfaces/user.utilities';

@Injectable()
export class UserDBService implements UserDBI {
  constructor(private readonly prisma: PrismaService) {}

  async findByUsernameOrEmail(
    username?: string,
    email?: string,
  ): Promise<UserEntity | null> {
    const user = await this.prisma.user.findFirst({
      where: { username, OR: [{ email }] },
      select: { id: true, email: true, passwordHash: true, username: true }, // minimal projection — we only need existence
    });
    if (user) {
      return {
        password: user.passwordHash || '',
        email: user.email,
        username: user.username,
        id: user.id,
      };
    } 
    return null
  }
  async updateUser(username: string, email: string, password: string): Promise<UserEntity> {
    const userUpdated = await this.prisma.user.update({
      where: { username: username },
      data: {
        email: email,
        passwordHash: password,
        username: username,
      },
    });
    if (userUpdated) {
      return {
        email: userUpdated.email,
        id: userUpdated.id,
        password: userUpdated.passwordHash || '',
        username: userUpdated.username,
      };
    } else {
      throw new Error('Not Found');
    }
  }
  async deleteUser(email: string): Promise<UserEntity> {
    const userUpdated = await this.prisma.user.delete({
      where: { email: email },
    });
    if (userUpdated) {
      return {
        email: userUpdated.email,
        password: userUpdated.passwordHash || '',
        username: userUpdated.username,
        id: userUpdated.id,
      };
    } else {
      throw new Error('Not Found');
    }
  }
  async createUser(username: string, email: string, password: string): Promise<UserEntity> {
    const user = await this.prisma.user.create({
      data: {
        email: email,
        username: username,
        passwordHash: password,
      },
    });

    return {
      id: user.id,
      email: user.email,
      password: user.passwordHash || '',
      username: user.username,
    };
  }
  async findById(id: string): Promise<UserEntity | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: id },
    });
    if (user) {
      return {
        id: user.id,
        email: user.email,
        password: user.passwordHash || '',
        username: user.username,
      };
    } 
    return null
  }
}
