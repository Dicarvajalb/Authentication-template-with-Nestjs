import { Controller, Get, UseGuards } from '@nestjs/common';
import { UserDBService } from '../services/user-db.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserDBService) {}
  @Get()
  getUsers() {
    return '[{{}}]';
  }
}
