import {
  Controller,
  Patch,
  Get,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import { InventoryService } from './inventory.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@Controller('inventory')
export class InventoryController {
  constructor(private readonly inventory: InventoryService) {}

  @Patch(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.SELLER, Role.ADMIN)
  adjust(
    @Param('id') id: string,
    @Body('qty') qty: number,
  ) {
    return this.inventory.adjust(id, qty);
  }

  @Get(':id')
  getStock(@Param('id') id: string) {
    return this.inventory.stock(id);
  }
}
