import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';
import { Transport, TcpOptions, RmqOptions } from '@nestjs/microservices';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

const log = new Logger('auth-svc');

const MS_TRANSPORT = process.env.MS_TRANSPORT ?? 'TCP';
const useTcp = MS_TRANSPORT === 'TCP';

// HTTP interno (Swagger) para debug
const HTTP_PORT = Number(process.env.SERVICE_PORT ?? 3102);

// Microservice TCP (usado por el gateway dentro de la red de Docker)
const TCP_HOST = process.env.MS_HOST ?? '0.0.0.0';
const TCP_PORT = Number(process.env.MS_TCP_PORT ?? 4040);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  if (useTcp) {
    app.connectMicroservice<TcpOptions>({
      transport: Transport.TCP,
      options: { host: TCP_HOST, port: TCP_PORT },
    });
    log.log(`MS (TCP) → ${TCP_HOST}:${TCP_PORT}`);
  } else {
    app.connectMicroservice<RmqOptions>({
      transport: Transport.RMQ,
      options: {
        urls: [process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672'],
        queue: process.env.RMQ_QUEUE || 'auth_queue',
        queueOptions: { durable: true },
      },
    });
  }

  await app.startAllMicroservices();

  const cfg = new DocumentBuilder()
    .setTitle('auth-svc (internal)')
    .setVersion('1.0.0')
    .build();
  const doc = SwaggerModule.createDocument(app, cfg, { deepScanRoutes: true });
  SwaggerModule.setup('docs', app, doc);

  await app.listen(HTTP_PORT, '0.0.0.0');
  log.log(`HTTP → http://0.0.0.0:${HTTP_PORT}`);
  log.log(`Swagger → http://0.0.0.0:${HTTP_PORT}/docs`);
}
bootstrap();
