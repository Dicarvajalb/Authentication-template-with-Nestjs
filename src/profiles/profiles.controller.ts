import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { CreateProfilesDTO } from './dto/CreateProfiles.dto';

@Controller('profiles')
export class ProfilesController {
  @Get()
  findAll(@Query('age') age: number) {
    return [{ age }];
  }
  @Get(':id')
  findOne(@Param('id') id: string) {
    return { id };
  }
  @Post()
  createOne(@Body() profile: CreateProfilesDTO) {
    return { name: profile.name, descrip: profile.description };
  }
}
