import { Module } from '@nestjs/common';
import { ProductsService } from './products.service';
import { ProductsController } from './products.controller';
import { ProductsRepository } from './products.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [ProductsController],
  providers: [ProductsService, ProductsRepository, PrismaService],
})
export class ProductsModule {}
