import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { RequestMethod } from '@nestjs/common';

async function bootstrap() {
  const port = process.env.PORT || 8000;
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api', { exclude: [
    { path: '/' , method: RequestMethod.GET}
  ]});
  app.enableCors({
    origin: "*",
    methods: ["GET", "POST","PATCH","DELETE","PUT"],
  });
  await app.listen(port);
}
bootstrap();
