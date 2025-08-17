import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { PATTERN } from './patterns';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './dto/auth.dto';

@Controller()
export class AuthController {
  constructor(private readonly svc: AuthService) {}
  @MessagePattern(PATTERN.Auth_Register) register(@Payload() dto: RegisterDto) { return this.svc.register(dto); }
  @MessagePattern(PATTERN.Auth_Login)    login(@Payload() dto: LoginDto)       { return this.svc.login(dto); }
  @MessagePattern(PATTERN.Auth_Refresh)  refresh(@Payload() p: { sub: string; orgId: string }) { return this.svc.refresh(p); }
}
