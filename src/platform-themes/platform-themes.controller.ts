import { Controller, Get } from '@nestjs/common';

@Controller('platform/themes')
export class PlatformThemesController {
  @Get()
  getThemes() {
    return [
      { id: 'dark', name: 'Default Dark' },
      { id: 'light', name: 'Default Light' },
      { id: 'gryffindor', name: 'Gryffindor' },
      { id: 'slytherin', name: 'Slytherin' },
      { id: 'ollivanders', name: 'Ollivanders' },
      { id: 'gringotts', name: 'Gringotts' },
      { id: 'wholesale', name: 'Wholesale B2B' },
      { id: 'halloween', name: 'Halloween Special' },
      { id: 'winter', name: 'Winter Wonderland' }
    ];
  }
}

