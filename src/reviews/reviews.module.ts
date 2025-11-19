import { Module } from '@nestjs/common';
import { ReviewsService } from './reviews.service';
import { ReviewsController } from './reviews.controller';
import { ReviewsRepository } from './reviews.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [ReviewsController],
  providers: [ReviewsService, ReviewsRepository, PrismaService],
})
export class ReviewsModule {}
