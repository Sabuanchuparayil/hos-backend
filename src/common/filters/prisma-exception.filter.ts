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
