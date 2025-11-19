import { Module } from '@nestjs/common';
import { OrdersService } from './orders.service';
import { OrdersController } from './orders.controller';
import { OrdersRepository } from './orders.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [OrdersController],
  providers: [OrdersService, OrdersRepository, PrismaService],
})
export class OrdersModule {}
