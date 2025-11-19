import { Module } from '@nestjs/common';
import { SellersService } from './sellers.service';
import { SellersController } from './sellers.controller';
import { SellersRepository } from './sellers.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [SellersController],
  providers: [SellersService, SellersRepository, PrismaService],
})
export class SellersModule {}
