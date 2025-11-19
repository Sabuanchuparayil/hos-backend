import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { Role } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const hashed = await bcrypt.hash(dto.password, 10);

    return this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        password: hashed,
        role: dto.role || Role.CUSTOMER,
      },
    });
  }

  async login(dto: any) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) throw new Error('Invalid credentials');

    const valid = await bcrypt.compare(dto.password, user.password);
    if (!valid) throw new Error('Invalid credentials');

    const accessToken = this.jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      { secret: process.env.JWT_SECRET, expiresIn: '1h' },
    );

    const refreshToken = this.jwt.sign(
      { id: user.id },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
    );

    return { user, accessToken, refreshToken };
  }

  async refresh(token: string) {
    const payload = this.jwt.verify(token, {
      secret: process.env.JWT_REFRESH_SECRET,
    });

    const user = await this.prisma.user.findUnique({
      where: { id: payload.id },
    });

    if (!user) throw new Error('Invalid refresh');

    const accessToken = this.jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      { secret: process.env.JWT_SECRET, expiresIn: '1h' },
    );

    return { accessToken };
  }
}
