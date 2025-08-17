import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaClient } from '@prisma/client';
import { Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom } from 'rxjs';
import { randomUUID } from 'crypto';
import { USERS } from './users-patterns-proxy';
import { RegisterDto, LoginDto } from './dto/auth.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaClient,
    @Inject('USERS_CLIENT') private readonly usersClient: ClientProxy,
  ) {}

  private buildAccessPayload(user: any) {
    const roles = (user.roles ?? []).map((r: any) => r.role.key);
    const name = user.patient?.fullName ?? user.staff?.fullName ?? '';
    const profile =
      user.patient ? 'PATIENT' :
      roles.includes('ORG_ADMIN') ? 'ORG_ADMIN' :
      roles.includes('CENTER_ADMIN') ? 'CENTER_ADMIN' : 'PATIENT';
    const centerId = user.staff?.centerId ?? null;

    return { sub: user.id, orgId: user.orgId, email: user.email, name, profile, centerId, roles, jti: randomUUID() };
  }

  private getAccessTtlSeconds(profile: string): number | null {
    const admin = Number(process.env.ADMIN_ACCESS_TTL_SEC ?? 7200);
    const patient = Number(process.env.PATIENT_ACCESS_TTL_SEC ?? 0);
    return (profile === 'ORG_ADMIN' || profile === 'CENTER_ADMIN') ? admin : (patient > 0 ? patient : null);
  }

  private async signAccess(payload: any) {
    const ttl = this.getAccessTtlSeconds(payload.profile);
    const now = Math.floor(Date.now() / 1000);
    const token = await this.jwt.signAsync(payload, ttl ? { expiresIn: ttl } : {});
    return { token, expiresIn: ttl ?? null, expiresAt: ttl ? new Date((now + ttl) * 1000).toISOString() : null };
  }

  private async signRefresh(userId: string, orgId: string) {
    const ttl = Number(process.env.REFRESH_TTL_SEC ?? 604800);
    const now = Math.floor(Date.now() / 1000);
    const token = await this.jwt.signAsync({ sub: userId, orgId, typ: 'refresh', jti: randomUUID() }, { expiresIn: ttl });
    return { token, expiresIn: ttl, expiresAt: new Date((now + ttl) * 1000).toISOString() };
  }

  async register(dto: RegisterDto) {
    const created = await lastValueFrom(this.usersClient.send('Users.Register', dto));
    if (created?.status === 'PENDING_APPROVAL') {
      return { status: 'PENDING_APPROVAL', requestId: created.requestId, userId: created.userId };
    }
    const hash = bcrypt.hashSync(dto.password, 10);
    await this.prisma.credential.create({ data: { orgId: created.orgId, userId: created.id, email: created.email, passwordHash: hash } });
    const payload = this.buildAccessPayload(created);
    const access = await this.signAccess(payload);
    const refresh = await this.signRefresh(created.id, created.orgId);
    return {
      accessToken: access.token, accessTokenExpiresIn: access.expiresIn, accessTokenExpiresAt: access.expiresAt,
      refreshToken: refresh.token, refreshTokenExpiresIn: refresh.expiresIn, refreshTokenExpiresAt: refresh.expiresAt,
      user: payload,
    };
  }

  async login(dto: LoginDto) {
    const cred = await this.prisma.credential.findUnique({ where: { orgId_email: { orgId: dto.orgId, email: dto.email } } as any });
    if (!cred) throw new UnauthorizedException('Bad credentials');

    const ok = bcrypt.compareSync(dto.password, cred.passwordHash);
    if (!ok) throw new UnauthorizedException('Bad credentials');

    const user = await lastValueFrom(this.usersClient.send('Users.GetById', cred.userId));
    const payload = this.buildAccessPayload(user);
    const access = await this.signAccess(payload);
    const refresh = await this.signRefresh(user.id, user.orgId);
    return {
      accessToken: access.token, accessTokenExpiresIn: access.expiresIn, accessTokenExpiresAt: access.expiresAt,
      refreshToken: refresh.token, refreshTokenExpiresIn: refresh.expiresIn, refreshTokenExpiresAt: refresh.expiresAt,
      user: payload,
    };
  }

  async refresh(p: { sub: string; orgId: string }) {
    const user = await lastValueFrom(this.usersClient.send('Users.GetById', p.sub));
    const payload = this.buildAccessPayload(user);
    const access = await this.signAccess(payload);
    return { accessToken: access.token, accessTokenExpiresIn: access.expiresIn, accessTokenExpiresAt: access.expiresAt, user: payload };
  }
}
