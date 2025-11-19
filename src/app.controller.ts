import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from '@nestjs/passport';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  // 🔒 PROTECTED ROUTE (JWT REQUIRED)
  @Get('protected')
  @UseGuards(AuthGuard('jwt'))
  getProtected() {
    return {
      message: 'Protected OK',
      time: new Date().toISOString(),
    };
  }
}

