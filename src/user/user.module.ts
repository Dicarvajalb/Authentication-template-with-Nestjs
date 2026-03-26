import { Module } from '@nestjs/common';
import { PrismaModule } from 'src/prisma/prisma.module';
import { UserDBService } from './services/user-db.service';
import { UserCRUDService } from './services/user-crud.service';

@Module({
  controllers: [],
  providers: [UserCRUDService, UserDBService],
  imports: [PrismaModule],
  exports: [UserCRUDService],
})
export class UserModule {}
