import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cors from 'cors';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Express CORS middleware
  app.use(cors({
    origin: [
      "https://hos-world-production.up.railway.app",
      "http://localhost:5173",
      "http://localhost:3000"
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
  }));

  // NestJS built-in CORS
  app.enableCors({
    origin: [
      "https://hos-world-production.up.railway.app",
      "http://localhost:5173",
      "http://localhost:3000"
    ],
    credentials: true
  });

  await app.listen(process.env.PORT || 3000);
  console.log("Backend running on PORT", process.env.PORT || 3000);
}

bootstrap();
