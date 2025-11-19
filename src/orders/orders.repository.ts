import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class OrdersRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.order.create({
      data,
      include: { items: true },
    });
  }

  findAll() {
    return this.prisma.order.findMany({
      include: { items: true },
    });
  }

  findOne(id: number) {
    return this.prisma.order.findUnique({
      where: { id },
      include: { items: true },
    });
  }

  update(id: number, data: any) {
    return this.prisma.order.update({
      where: { id },
      data,
    });
  }

  remove(id: number) {
    return this.prisma.order.delete({ where: { id } });
  }
}
