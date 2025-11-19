import { Injectable } from '@nestjs/common';
import { InventoryRepository } from './inventory.repository';

@Injectable()
export class InventoryService {
  constructor(private repo: InventoryRepository) {}

  adjust(productId: string, qty: number) {
    return this.repo.adjustStock(Number(productId), qty);
  }

  stock(productId: string) {
    return this.repo.getStock(Number(productId));
  }
}
