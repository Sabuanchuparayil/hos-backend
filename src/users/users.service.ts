import { Injectable } from '@nestjs/common';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcryptjs';
import { Role } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(private repo: UsersRepository) {}

  async create(data: any) {
    data.password = await bcrypt.hash(data.password, 10);
    data.role = data.role || Role.USER;
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  async update(id: string, data: any) {
    if (data.password) {
      data.password = await bcrypt.hash(data.password, 10);
    }
    return this.repo.update(Number(id), data);
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
