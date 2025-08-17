import 'dotenv/config';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ConfigModule } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

const useTcp = process.env.MS_TRANSPORT === 'TCP';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.register({ secret: process.env.JWT_SECRET || 'dev-secret', signOptions: { issuer: 'auth-svc' } }),
    ClientsModule.register([
      useTcp
        ? { name: 'USERS_CLIENT', transport: Transport.TCP, options: { host: '127.0.0.1', port: 4030 } }
        : { name: 'USERS_CLIENT', transport: Transport.RMQ, options: {
            urls: [process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672'],
            queue: 'users_queue', queueOptions: { durable: true } } },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaClient],
})
export class AppModule {}
