import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RolesGuard } from '../common/guards/roles.guard';
import { Role } from '@prisma/client';

@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  // Admin: create new user
  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  create(@Body() dto: any) {
    return this.users.create(dto);
  }

  // Admin: view all users
  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  findAll() {
    return this.users.findAll();
  }

  // Any user: view own profile
  @Get(':id')
  @UseGuards(JwtAuthGuard)
  findOne(@Param('id') id: string) {
    return this.users.findOne(id);
  }

  // Admin: update any user
  @Put(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  update(@Param('id') id: string, @Body() dto: any) {
    return this.users.update(id, dto);
  }

  // Admin: delete user
  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  remove(@Param('id') id: string) {
    return this.users.remove(id);
  }
}
