import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class SellersRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.seller.create({ data });
  }

  findAll() {
    return this.prisma.seller.findMany();
  }

  findOne(id: number) {
    return this.prisma.seller.findUnique({ where: { id } });
  }

  update(id: number, data: any) {
    return this.prisma.seller.update({ where: { id }, data });
  }

  remove(id: number) {
    return this.prisma.seller.delete({ where: { id } });
  }
}
