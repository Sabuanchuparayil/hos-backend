import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // FIXED CORS CONFIG
  app.enableCors({
    origin: [
      'https://hos-world-production.up.railway.app',
      'http://localhost:5173',
      'http://localhost:3000'
    ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
    allowedHeaders: 'Content-Type, Authorization'
  });

  await app.listen(process.env.PORT || 3000);
  console.log(`Backend running on port ${process.env.PORT || 3000}`);
}

bootstrap();
