import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma, User } from '../generated/prisma/browser';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async findUnique(params: Prisma.UserFindUniqueArgs): Promise<User | null> {
    return this.prisma.user.findUnique(params);
  }
  async createUnique(params: Prisma.UserCreateArgs): Promise<User | null> {
    console.log('⚙️ ~ UserService ~ createUnique ~ params:', params);
    return this.prisma.user.create(params);
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

  async createUser(data: Prisma.UserCreateInput): Promise<User> {
    return this.prisma.user.create({
      data,
    });
  }

  async updateUser(params: {
    where: Prisma.UserWhereUniqueInput;
    data: Prisma.UserUpdateInput;
  }): Promise<User> {
    const { where, data } = params;
    return this.prisma.user.update({
      data,
      where,
    });
  }

  async deleteUser(params: Prisma.UserDeleteArgs): Promise<User> {
    return this.prisma.user.delete(params);
  }
}
