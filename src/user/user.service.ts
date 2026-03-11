import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma, User } from '../generated/prisma/browser';
import { UserEntity } from './entities/user.entities';
import { UserRepository } from './entities/user.repository';

@Injectable()
export class UserService implements UserRepository {
  constructor(private prisma: PrismaService) {}

  async findUnique(params: Prisma.UserFindUniqueArgs): Promise<User | null> {
    return this.prisma.user.findUnique(params);
  }
  async createUnique(params: Prisma.UserCreateArgs): Promise<User | null> {
    return this.prisma.user.create(params);
  }
  async findFirst(params: Prisma.UserFindFirstArgs): Promise<User | null> {
    return this.prisma.user.findFirst(params);
  }

  async users(params: {
    skip?: number;
    take?: number;
    cursor?: Prisma.UserWhereUniqueInput;
    where?: Prisma.UserWhereInput;
    orderBy?: Prisma.UserOrderByWithRelationInput;
  }): Promise<User[]> {
    const { skip, take, cursor, where, orderBy } = params;
    return this.prisma.user.findMany({
      skip,
      take,
      cursor,
      where,
      orderBy,
    });
  }

  async createUser(data: UserEntity): Promise<UserEntity> {
    const user = await this.prisma.user.create({
      data,
    });

    return {
      email: user.email,
      password: user.passwordHash || '',
      username: user.username,
    };
  }
  deleteUser(user: UserEntity): Promise<UserEntity> {
    return Promise.resolve(user);
  }
  updateUser(user: UserEntity): Promise<UserEntity> {
    return Promise.resolve(user);
  }
  async findUser(username: string, email: string): Promise<UserEntity> {
    const user = await this.prisma.user.findFirst({
      where: { username, OR: [{ email }] },
      select: { id: true, email: true, passwordHash: true, username: true }, // minimal projection — we only need existence
    });
    if (user) {
      return {
        email: user.email,
        password: user.passwordHash || '',
        username: user.username,
      };
    } else {
      throw new Error('Not Found');
    }
  }
}
