import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/common/guards/jwt-cookie.guard';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  @UseGuards(AuthGuard)
  @Get()
  async getUsers() {
    /*console.log('⚙️ ~ AuthController ~ signUp ~ data:', data);
        try {
          const token = await this.authService.signUp({
            data: { password: data.password, username: data.username },
          });
    
          return token;
        } catch (error) {
          throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
        */
    return await this.userService.users({});
  }
}
