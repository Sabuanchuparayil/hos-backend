import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Role } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async create(data: CreateUserDto) {
    return this.prisma.user.create({
      data: {
        email: data.email,
        password: data.password,
        name: data.name,
        role: (data.role as Role) || Role.CUSTOMER,
      },
    });
  }

  async findAll() {
    return this.prisma.user.findMany();
  }

  async findOne(id: string) {
    return this.prisma.user.findUnique({
      where: { id: Number(id) },   // FIXED
    });
  }

  async update(id: string, data: UpdateUserDto) {
    return this.prisma.user.update({
      where: { id: Number(id) },   // FIXED
      data: {
        ...data,
        role: data.role ? (data.role as Role) : undefined,
      },
    });
  }

  async remove(id: string) {
    return this.prisma.user.delete({
      where: { id: Number(id) },   // FIXED
    });
  }
}

