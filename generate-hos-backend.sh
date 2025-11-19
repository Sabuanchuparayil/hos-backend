echo "Generating Prisma schema..."

mkdir -p prisma

cat > prisma/schema.prisma <<'PRISMA'
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id        Int      @id @default(autoincrement())
  name      String
  email     String   @unique
  password  String
  role      Role     @default(USER)
  createdAt DateTime @default(now())
  orders    Order[]
  reviews   Review[]
}

model Seller {
  id        Int       @id @default(autoincrement())
  name      String
  email     String     @unique
  phone     String?
  isActive  Boolean    @default(true)
  products  Product[]
  orders    Order[]
  createdAt DateTime   @default(now())
}

model Product {
  id          Int        @id @default(autoincrement())
  name        String
  description String?
  price       Float
  stock       Int        @default(0)
  sellerId    Int
  seller      Seller     @relation(fields: [sellerId], references: [id])
  reviews     Review[]
  orders      OrderItem[]
  createdAt   DateTime   @default(now())
}

model Order {
  id          Int         @id @default(autoincrement())
  userId      Int
  sellerId    Int
  status      OrderStatus @default(PENDING)
  total       Float
  createdAt   DateTime    @default(now())
  user        User        @relation(fields: [userId], references: [id])
  seller      Seller      @relation(fields: [sellerId], references: [id])
  items       OrderItem[]
}

model OrderItem {
  id        Int      @id @default(autoincrement())
  orderId   Int
  productId Int
  quantity  Int
  price     Float
  order     Order    @relation(fields: [orderId], references: [id])
  product   Product  @relation(fields: [productId], references: [id])
}

model Review {
  id        Int      @id @default(autoincrement())
  rating    Int
  comment   String?
  userId    Int
  productId Int
  createdAt DateTime @default(now())
  user      User     @relation(fields: [userId], references: [id])
  product   Product  @relation(fields: [productId], references: [id])
}

enum Role {
  ADMIN
  SELLER
  USER
  CUSTOMER
}

enum OrderStatus {
  PENDING
  CONFIRMED
  SHIPPED
  DELIVERED
  CANCELLED
}
PRISMA

echo "✔ Prisma schema created."
#!/usr/bin/env bash
echo "HOS Backend Generator Running..."

set -euo pipefail
root="$(pwd)"
echo "Working directory: $root"
echo "Starting HOS Enterprise Backend Generator..."

echo "Generating COMMON layer..."

mkdir -p src/common/decorators src/common/guards src/common/interceptors src/common/filters

# --- Roles Decorator ---
cat > src/common/decorators/roles.decorator.ts <<'TS'
import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client';
export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
TS

# --- User Decorator ---
cat > src/common/decorators/user.decorator.ts <<'TS'
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
export const User = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    return data ? user?.[data] : user;
  },
);
TS

# --- JWT Guard ---
cat > src/common/guards/jwt-auth.guard.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
TS

# --- Roles Guard ---
cat > src/common/guards/roles.guard.ts <<'TS'
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '@prisma/client';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (!requiredRoles) return true;

    const { user } = ctx.switchToHttp().getRequest();
    if (!user || !requiredRoles.includes(user.role)) {
      throw new ForbiddenException('You do not have access to this resource');
    }

    return true;
  }
}
TS

# --- Global Response Interceptor ---
cat > src/common/interceptors/response.interceptor.ts <<'TS'
import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler) {
    return next.handle().pipe(
      map(data => ({
        success: true,
        timestamp: new Date().toISOString(),
        data,
      })),
    );
  }
}
TS

# --- HTTP Exception Filter ---
cat > src/common/filters/http-exception.filter.ts <<'TS'
import { ExceptionFilter, Catch, ArgumentsHost, HttpException } from '@nestjs/common';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const status = exception.getStatus();

    response.status(status).json({
      success: false,
      statusCode: status,
      message: exception.message,
      timestamp: new Date().toISOString(),
    });
  }
}
TS

# --- Prisma Exception Filter ---
cat > src/common/filters/prisma-exception.filter.ts <<'TS'
import { ExceptionFilter, Catch, ArgumentsHost } from '@nestjs/common';
import { Prisma } from '@prisma/client';

@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaExceptionFilter implements ExceptionFilter {
  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse();

    response.status(400).json({
      success: false,
      error: 'Database Error',
      code: exception.code,
      message: exception.message,
      timestamp: new Date().toISOString(),
    });
  }
}
TS

echo "✔ Common layer created."

echo "Generating Prisma Service..."

mkdir -p src/prisma

cat > src/prisma/prisma.service.ts <<'TS'
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
TS

echo "✔ PrismaService created."

echo "Generating AUTH module..."

mkdir -p src/auth/dto src/auth/strategies

# --- Register DTO ---
cat > src/auth/dto/register.dto.ts <<'TS'
import { Role } from '@prisma/client';

export class RegisterDto {
  name: string;
  email: string;
  password: string;
  role?: Role;
}
TS

# --- Login DTO ---
cat > src/auth/dto/login.dto.ts <<'TS'
export class LoginDto {
  email: string;
  password: string;
}
TS

# --- JWT Strategy ---
cat > src/auth/strategies/jwt.strategy.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET || 'defaultsecret',
    });
  }

  async validate(payload: any) {
    return payload;
  }
}
TS

# --- Refresh Token Strategy ---
cat > src/auth/strategies/refresh.strategy.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(Strategy, 'refresh') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_REFRESH_SECRET || 'defaultrefreshsecret',
    });
  }

  async validate(payload: any) {
    return payload;
  }
}
TS

# --- Auth Service ---
cat > src/auth/auth.service.ts <<'TS'
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
TS

# --- Auth Controller ---
cat > src/auth/auth.controller.ts <<'TS'
import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto);
  }

  @Post('refresh')
  refresh(@Body('token') token: string) {
    return this.auth.refresh(token);
  }
}
TS

# --- Auth Module ---
cat > src/auth/auth.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshJwtStrategy } from './strategies/refresh.strategy';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, JwtStrategy, RefreshJwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
TS

echo "✔ Auth module created."
echo "Generating USERS module..."

mkdir -p src/users/dto src/users/interfaces

# --- CreateUser DTO ---
cat > src/users/dto/create-user.dto.ts <<'TS'
import { Role } from '@prisma/client';

export class CreateUserDto {
  name: string;
  email: string;
  password: string;
  role?: Role;
}
TS

# --- UpdateUser DTO ---
cat > src/users/dto/update-user.dto.ts <<'TS'
import { Role } from '@prisma/client';

export class UpdateUserDto {
  name?: string;
  email?: string;
  password?: string;
  role?: Role;
}
TS

# --- Users Repository ---
cat > src/users/users.repository.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UsersRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.user.create({ data });
  }

  findAll() {
    return this.prisma.user.findMany();
  }

  findOne(id: number) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  update(id: number, data: any) {
    return this.prisma.user.update({ where: { id }, data });
  }

  remove(id: number) {
    return this.prisma.user.delete({ where: { id } });
  }
}
TS

# --- Users Service ---
cat > src/users/users.service.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcryptjs';
import { Role } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(private repo: UsersRepository) {}

  async create(data: any) {
    data.password = await bcrypt.hash(data.password, 10);
    data.role = data.role || Role.USER;
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  async update(id: string, data: any) {
    if (data.password) {
      data.password = await bcrypt.hash(data.password, 10);
    }
    return this.repo.update(Number(id), data);
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
TS

# --- Users Controller ---
cat > src/users/users.controller.ts <<'TS'
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
TS

# --- Users Module ---
cat > src/users/users.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { UsersRepository } from './users.repository';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [UsersController],
  providers: [UsersRepository, UsersService, PrismaService],
  exports: [UsersService],
})
export class UsersModule {}
TS

echo "✔ Users module created."

echo "Generating SELLERS module..."

mkdir -p src/sellers/dto src/sellers/interfaces

cat > src/sellers/sellers.repository.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class SellersRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.seller.create({ data });
  }

  findAll() {
    return this.prisma.seller.findMany();
  }

  findOne(id: number) {
    return this.prisma.seller.findUnique({ where: { id } });
  }

  update(id: number, data: any) {
    return this.prisma.seller.update({ where: { id }, data });
  }

  remove(id: number) {
    return this.prisma.seller.delete({ where: { id } });
  }
}
TS

cat > src/sellers/sellers.service.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { SellersRepository } from './sellers.repository';

@Injectable()
export class SellersService {
  constructor(private repo: SellersRepository) {}

  create(data: any) {
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  update(id: string, data: any) {
    return this.repo.update(Number(id), data);
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
TS

cat > src/sellers/sellers.controller.ts <<'TS'
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
import { SellersService } from './sellers.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '@prisma/client';

@Controller('sellers')
export class SellersController {
  constructor(private readonly sellers: SellersService) {}

  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  create(@Body() dto: any) {
    return this.sellers.create(dto);
  }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  findAll() {
    return this.sellers.findAll();
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  findOne(@Param('id') id: string) {
    return this.sellers.findOne(id);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  update(@Param('id') id: string, @Body() dto: any) {
    return this.sellers.update(id, dto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  remove(@Param('id') id: string) {
    return this.sellers.remove(id);
  }
}
TS

cat > src/sellers/sellers.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { SellersService } from './sellers.service';
import { SellersController } from './sellers.controller';
import { SellersRepository } from './sellers.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [SellersController],
  providers: [SellersService, SellersRepository, PrismaService],
})
export class SellersModule {}
TS

echo "✔ Sellers module created."



#############################################################
#  PRODUCTS MODULE
#############################################################

echo "Generating PRODUCTS module..."

mkdir -p src/products/dto src/products/interfaces

cat > src/products/products.repository.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ProductsRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.product.create({ data });
  }

  findAll() {
    return this.prisma.product.findMany();
  }

  findOne(id: number) {
    return this.prisma.product.findUnique({ where: { id } });
  }

  update(id: number, data: any) {
    return this.prisma.product.update({ where: { id }, data });
  }

  remove(id: number) {
    return this.prisma.product.delete({ where: { id } });
  }
}
TS

cat > src/products/products.service.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { ProductsRepository } from './products.repository';

@Injectable()
export class ProductsService {
  constructor(private repo: ProductsRepository) {}

  create(data: any) {
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  update(id: string, data: any) {
    return this.repo.update(Number(id), data);
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
TS

cat > src/products/products.controller.ts <<'TS'
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
TS

cat > src/products/products.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { ProductsService } from './products.service';
import { ProductsController } from './products.controller';
import { ProductsRepository } from './products.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [ProductsController],
  providers: [ProductsService, ProductsRepository, PrismaService],
})
export class ProductsModule {}
TS

echo "✔ Products module created."



#############################################################
#  ORDERS MODULE
#############################################################

echo "Generating ORDERS module..."

mkdir -p src/orders/dto src/orders/interfaces

cat > src/orders/orders.repository.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class OrdersRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.order.create({
      data,
      include: { items: true },
    });
  }

  findAll() {
    return this.prisma.order.findMany({
      include: { items: true },
    });
  }

  findOne(id: number) {
    return this.prisma.order.findUnique({
      where: { id },
      include: { items: true },
    });
  }

  update(id: number, data: any) {
    return this.prisma.order.update({
      where: { id },
      data,
    });
  }

  remove(id: number) {
    return this.prisma.order.delete({ where: { id } });
  }
}
TS

cat > src/orders/orders.service.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { OrdersRepository } from './orders.repository';

@Injectable()
export class OrdersService {
  constructor(private repo: OrdersRepository) {}

  create(data: any) {
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  update(id: string, data: any) {
    return this.repo.update(Number(id), data);
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
TS

cat > src/orders/orders.controller.ts <<'TS'
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
TS

cat > src/orders/orders.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { OrdersService } from './orders.service';
import { OrdersController } from './orders.controller';
import { OrdersRepository } from './orders.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [OrdersController],
  providers: [OrdersService, OrdersRepository, PrismaService],
})
export class OrdersModule {}
TS

echo "✔ Orders module created."



#############################################################
#  REVIEWS MODULE
#############################################################

echo "Generating REVIEWS module..."

mkdir -p src/reviews/dto src/reviews/interfaces

cat > src/reviews/reviews.repository.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ReviewsRepository {
  constructor(private prisma: PrismaService) {}

  create(data: any) {
    return this.prisma.review.create({ data });
  }

  findAll() {
    return this.prisma.review.findMany();
  }

  findOne(id: number) {
    return this.prisma.review.findUnique({ where: { id } });
  }

  remove(id: number) {
    return this.prisma.review.delete({ where: { id } });
  }
}
TS

cat > src/reviews/reviews.service.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { ReviewsRepository } from './reviews.repository';

@Injectable()
export class ReviewsService {
  constructor(private repo: ReviewsRepository) {}

  create(data: any) {
    return this.repo.create(data);
  }

  findAll() {
    return this.repo.findAll();
  }

  findOne(id: string) {
    return this.repo.findOne(Number(id));
  }

  remove(id: string) {
    return this.repo.remove(Number(id));
  }
}
TS

cat > src/reviews/reviews.controller.ts <<'TS'
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
TS

cat > src/reviews/reviews.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { ReviewsService } from './reviews.service';
import { ReviewsController } from './reviews.controller';
import { ReviewsRepository } from './reviews.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [ReviewsController],
  providers: [ReviewsService, ReviewsRepository, PrismaService],
})
export class ReviewsModule {}
TS

echo "✔ Reviews module created."



#############################################################
#  INVENTORY MODULE
#############################################################

echo "Generating INVENTORY module..."

mkdir -p src/inventory/dto src/inventory/interfaces

cat > src/inventory/inventory.repository.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class InventoryRepository {
  constructor(private prisma: PrismaService) {}

  adjustStock(productId: number, change: number) {
    return this.prisma.product.update({
      where: { id: productId },
      data: { stock: { increment: change } },
    });
  }

  getStock(productId: number) {
    return this.prisma.product.findUnique({ where: { id: productId } });
  }
}
TS

cat > src/inventory/inventory.service.ts <<'TS'
import { Injectable } from '@nestjs/common';
import { InventoryRepository } from './inventory.repository';

@Injectable()
export class InventoryService {
  constructor(private repo: InventoryRepository) {}

  adjust(productId: string, qty: number) {
    return this.repo.adjustStock(Number(productId), qty);
  }

  stock(productId: string) {
    return this.repo.getStock(Number(productId));
  }
}
TS

cat > src/inventory/inventory.controller.ts <<'TS'
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
TS

cat > src/inventory/inventory.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { InventoryService } from './inventory.service';
import { InventoryController } from './inventory.controller';
import { InventoryRepository } from './inventory.repository';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [InventoryController],
  providers: [InventoryService, InventoryRepository, PrismaService],
})
export class InventoryModule {}
TS

echo "✔ Inventory module created."



#############################################################
#  APP MODULE + MAIN.TS
#############################################################

echo "Generating APP MODULE & MAIN..."

cat > src/app.module.ts <<'TS'
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { PrismaExceptionFilter } from './common/filters/prisma-exception.filter';

import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { SellersModule } from './sellers/sellers.module';
import { ProductsModule } from './products/products.module';
import { OrdersModule } from './orders/orders.module';
import { InventoryModule } from './inventory/inventory.module';
import { ReviewsModule } from './reviews/reviews.module';

@Module({
  imports: [
    AuthModule,
    UsersModule,
    SellersModule,
    ProductsModule,
    OrdersModule,
    InventoryModule,
    ReviewsModule,
  ],
  providers: [
    { provide: APP_INTERCEPTOR, useClass: ResponseInterceptor },
    { provide: APP_FILTER, useClass: HttpExceptionFilter },
    { provide: APP_FILTER, useClass: PrismaExceptionFilter },
  ],
})
export class AppModule {}
TS


cat > src/main.ts <<'TS'
import * as dotenv from 'dotenv';
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('HOS API')
    .setDescription('HOS Enterprise Backend')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, document);

  await app.listen(process.env.PORT || 3000);
  console.log('🚀 HOS Backend running at http://localhost:3000');
  console.log('📘 Swagger docs at http://localhost:3000/api-docs');
}
bootstrap();
TS

echo "✔ AppModule & main.ts created."
echo "---------------------------------------------"
echo "🎉 HOS ENTERPRISE BACKEND GENERATOR COMPLETED"
echo "---------------------------------------------"


