import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class InventoryRepository {
  constructor(private prisma: PrismaService) {}

  adjustStock(productId: number, change: number) {
    return this.prisma.product.update({
      where: { id: productId },
      data: { stock: { increment: change } },
    });
  }

  getStock(productId: number) {
    return this.prisma.product.findUnique({ where: { id: productId } });
  }
}
