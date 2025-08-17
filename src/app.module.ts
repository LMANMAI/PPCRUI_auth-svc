import 'dotenv/config';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import {
  ClientsModule,
  Transport,
  ClientProviderOptions,
} from '@nestjs/microservices';
import { ConfigModule } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

const useTcp = (process.env.MS_TRANSPORT ?? 'TCP') === 'TCP';
const useUsers = (process.env.USERS_MS ?? 'off') === 'on';

const USERS_CLIENT_TCP: ClientProviderOptions = {
  name: 'USERS_CLIENT',
  transport: Transport.TCP,
  options: {
    host: process.env.USERS_HOST || '127.0.0.1',
    port: Number(process.env.USERS_PORT || 4030),
  },
};

const USERS_CLIENT_RMQ: ClientProviderOptions = {
  name: 'USERS_CLIENT',
  transport: Transport.RMQ,
  options: {
    urls: [process.env.RABBITMQ_URL || 'amqp://guest:guest@localhost:5672'],
    queue: 'users_queue',
    queueOptions: { durable: true },
  },
};

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'dev-secret',
      signOptions: { issuer: 'auth-svc' },
    }),
    ...(useUsers
      ? [ClientsModule.register([useTcp ? USERS_CLIENT_TCP : USERS_CLIENT_RMQ])]
      : []),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaClient],
})
export class AppModule {}
