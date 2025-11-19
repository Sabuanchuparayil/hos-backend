import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ProductsRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.product.create({ data });
  }

  findAll() {
    return this.prisma.product.findMany();
  }

  findOne(id: number) {
    return this.prisma.product.findUnique({ where: { id } });
  }

  update(id: number, data: any) {
    return this.prisma.product.update({ where: { id }, data });
  }

  remove(id: number) {
    return this.prisma.product.delete({ where: { id } });
  }
}
