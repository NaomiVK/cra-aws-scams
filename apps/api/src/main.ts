/**
 * CRA Scam Detection API
 * Backend service for detecting potential scams in Google Search Console data
 */

import * as dotenv from 'dotenv';
dotenv.config(); // Load .env file

import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app/app.module';
import { environment } from './environments/environment';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Set global API prefix
  const globalPrefix = 'api';
  app.setGlobalPrefix(globalPrefix);

  // Enable CORS for Angular frontend
  // In production behind nginx, allow all origins (nginx proxies requests)
  // In development, restrict to the frontend URL
  app.enableCors({
    origin: environment.frontendUrl === '*' ? true : environment.frontendUrl,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Password'],
  });

  // Get port from environment
  const port = environment.port;

  await app.listen(port);

  Logger.log(
    `🚀 CRA Scam Detection API is running on: http://localhost:${port}/${globalPrefix}`
  );
  Logger.log(`📊 Environment: ${environment.production ? 'production' : 'development'}`);
  Logger.log(`🎯 Target site: ${environment.google.siteUrl}`);
  Logger.log(`📈 Impression threshold: ${environment.scamDetection.impressionThreshold}`);
}

bootstrap();
