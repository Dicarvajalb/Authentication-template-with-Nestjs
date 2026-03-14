import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/common/guards/jwt-cookie.guard';
import { UserDBService } from '../services/user-db.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserDBService) {}
  @UseGuards(AuthGuard)
  @Get()
  getUsers() {
    return '[{{}}]';
  }
}
