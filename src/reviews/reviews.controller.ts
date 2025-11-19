import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { ReviewsService } from './reviews.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';

@Controller('reviews')
export class ReviewsController {
  constructor(private readonly reviews: ReviewsService) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  create(@Body() dto: any) {
    return this.reviews.create(dto);
  }

  @Get()
  findAll() {
    return this.reviews.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.reviews.findOne(id);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  remove(@Param('id') id: string) {
    return this.reviews.remove(id);
  }
}
