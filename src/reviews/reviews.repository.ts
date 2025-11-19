import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ReviewsRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.review.create({ data });
  }

  findAll() {
    return this.prisma.review.findMany();
  }

  findOne(id: number) {
    return this.prisma.review.findUnique({ where: { id } });
  }

  remove(id: number) {
    return this.prisma.review.delete({ where: { id } });
  }
}
