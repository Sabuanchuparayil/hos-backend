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
import { ProductsService } from './products.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@Controller('products')
export class ProductsController {
  constructor(private readonly products: ProductsService) {}

  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.SELLER, Role.ADMIN)
  create(@Body() dto: any) {
    return this.products.create(dto);
  }

  @Get()
  findAll() {
    return this.products.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.products.findOne(id);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.SELLER, Role.ADMIN)
  update(@Param('id') id: string, @Body() dto: any) {
    return this.products.update(id, dto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.SELLER, Role.ADMIN)
  remove(@Param('id') id: string) {
    return this.products.remove(id);
  }
}
