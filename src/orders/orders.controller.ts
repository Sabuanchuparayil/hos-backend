import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  Put,
  UseGuards,
} from '@nestjs/common';
import { OrdersService } from './orders.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@Controller('orders')
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  create(@Body() dto: any) {
    return this.orders.create(dto);
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  findAll() {
    return this.orders.findAll();
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  findOne(@Param('id') id: string) {
    return this.orders.findOne(id);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard)
  update(@Param('id') id: string, @Body() dto: any) {
    return this.orders.update(id, dto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  remove(@Param('id') id: string) {
    return this.orders.remove(id);
  }
}
