import { Injectable } from '@nestjs/common';
import { OrdersRepository } from './orders.repository';

@Injectable()
export class OrdersService {
  constructor(private repo: OrdersRepository) {}

  create(data: any) {
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  update(id: string, data: any) {
    return this.repo.update(Number(id), data);
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
