import { Module } from '@nestjs/common';
import { PlatformThemesController } from './platform-themes.controller';

@Module({
  controllers: [PlatformThemesController],
})
export class PlatformThemesModule {}

