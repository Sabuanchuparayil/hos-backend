import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { Role } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  // REGISTER USER
  async register(dto: RegisterDto) {
    const hashed = await bcrypt.hash(dto.password, 10);

    return this.prisma.user.create({
      data: {
        email: dto.email,
        password: hashed,
        name: dto.name,
        role: dto.role || Role.CUSTOMER,
      },
    });
  }

  // LOGIN USER
  async login(dto: RegisterDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new Error('User not found');
    }

    const valid = await bcrypt.compare(dto.password, user.password);
    if (!valid) {
      throw new Error('Invalid password');
    }

    const accessToken = this.jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      { secret: process.env.JWT_SECRET, expiresIn: '1h' },
    );

    const refreshToken = this.jwt.sign(
      { id: user.id },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
    );

    return {
      user,
      accessToken,
      refreshToken,
    };
  }

  // REFRESH TOKEN
  async refresh(token: string) {
    const payload = this.jwt.verify(token, {
      secret: process.env.JWT_REFRESH_SECRET,
    });

    const user = await this.prisma.user.findUnique({
      where: { id: payload.id },
    });

    if (!user) {
      throw new Error('User not found');
    }

    const accessToken = this.jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      { secret: process.env.JWT_SECRET, expiresIn: '1h' },
    );

    return { accessToken };
  }
}

