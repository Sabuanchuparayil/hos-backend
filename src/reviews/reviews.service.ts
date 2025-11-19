import { Injectable } from '@nestjs/common';
import { ReviewsRepository } from './reviews.repository';

@Injectable()
export class ReviewsService {
  constructor(private repo: ReviewsRepository) {}

  create(data: any) {
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
