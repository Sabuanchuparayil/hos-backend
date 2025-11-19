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
