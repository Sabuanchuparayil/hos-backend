import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Post('login')
  async login(@Body() dto: RegisterDto) {
    return this.auth.login(dto);
  }

  @Post('refresh')
  async refresh(@Body('token') token: string) {
    return this.auth.refresh(token);
  }
}

