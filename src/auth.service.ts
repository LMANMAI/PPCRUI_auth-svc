import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'crypto';
import { RegisterDto, LoginDto } from './dto/auth.dto';
import * as bcrypt from 'bcryptjs';

function rolesFromProfile(
  p?: 'PATIENT' | 'CENTER_ADMIN' | 'ORG_ADMIN',
): string[] {
  if (p === 'ORG_ADMIN') return ['ORG_ADMIN'];
  if (p === 'CENTER_ADMIN') return ['CENTER_ADMIN'];
  return [];
}

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaClient,
  ) {}

  private buildAccessPayload(user: any) {
    const roles: string[] = (user.roles ?? []).map(
      (r: any) => r?.role?.key ?? r,
    );
    const name = user.patient?.fullName ?? user.staff?.fullName ?? '';
    const profile = user.patient
      ? 'PATIENT'
      : roles.includes('ORG_ADMIN')
        ? 'ORG_ADMIN'
        : roles.includes('CENTER_ADMIN')
          ? 'CENTER_ADMIN'
          : 'PATIENT';
    const centerId = user.staff?.centerId ?? null;

    return {
      sub: user.id,
      orgId: user.orgId,
      email: user.email,
      name,
      profile,
      centerId,
      roles,
      jti: randomUUID(),
    };
  }

  private getAccessTtlSeconds(profile: string): number | null {
    const admin = Number(process.env.ADMIN_ACCESS_TTL_SEC ?? 7200);
    const patient = Number(process.env.PATIENT_ACCESS_TTL_SEC ?? 0);
    return profile === 'ORG_ADMIN' || profile === 'CENTER_ADMIN'
      ? admin
      : patient > 0
        ? patient
        : null;
  }

  private async signAccess(payload: any) {
    const ttl = this.getAccessTtlSeconds(payload.profile);
    const now = Math.floor(Date.now() / 1000);
    const token = await this.jwt.signAsync(
      payload,
      ttl ? { expiresIn: ttl } : {},
    );
    return {
      token,
      expiresIn: ttl ?? null,
      expiresAt: ttl ? new Date((now + ttl) * 1000).toISOString() : null,
    };
  }

  private async signRefresh(userId: string, orgId: string) {
    const ttl = Number(process.env.REFRESH_TTL_SEC ?? 604800);
    const now = Math.floor(Date.now() / 1000);
    const token = await this.jwt.signAsync(
      { sub: userId, orgId, typ: 'refresh', jti: randomUUID() },
      { expiresIn: ttl },
    );
    return {
      token,
      expiresIn: ttl,
      expiresAt: new Date((now + ttl) * 1000).toISOString(),
    };
  }

  async register(dto: RegisterDto) {
    const existing = await this.prisma.credential.findUnique({
      where: { orgId_email: { orgId: dto.orgId, email: dto.email } } as any,
    });

    if (existing) {
      return {
        ok: false,
        status: 'ALREADY_REGISTERED',
        error: {
          code: 'EMAIL_EXISTS',
          message:
            'Ya existe una cuenta registrada con ese email para esta organización.',
        },
      };
    }

    const created = {
      id: randomUUID(),
      orgId: dto.orgId,
      email: dto.email,
      patient:
        dto.profileType === 'PATIENT' ? { fullName: dto.fullName ?? '' } : null,
      staff:
        dto.profileType !== 'PATIENT'
          ? {
              fullName: dto.staffFullName ?? dto.fullName ?? '',
              centerId: dto.centerId ?? null,
            }
          : null,
      roles:
        dto.profileType === 'ORG_ADMIN'
          ? [{ role: { key: 'ORG_ADMIN' } }]
          : dto.profileType === 'CENTER_ADMIN'
            ? [{ role: { key: 'CENTER_ADMIN' } }]
            : [],
    };

    const hash = bcrypt.hashSync(dto.password, 10);
    await this.prisma.credential.create({
      data: {
        orgId: created.orgId,
        userId: created.id,
        email: created.email,
        passwordHash: hash,
        profile: dto.profileType as any,
        name: dto.staffFullName ?? dto.fullName ?? null,
        centerId: dto.centerId ?? null,
      } as any,
    });

    const payload = this.buildAccessPayload(created);
    const access = await this.signAccess(payload);
    const refresh = await this.signRefresh(created.id, created.orgId);

    return {
      ok: true,
      status: 'CREATED',
      accessToken: access.token,
      accessTokenExpiresIn: access.expiresIn,
      accessTokenExpiresAt: access.expiresAt,
      refreshToken: refresh.token,
      refreshTokenExpiresIn: refresh.expiresIn,
      refreshTokenExpiresAt: refresh.expiresAt,
      user: payload,
    };
  }

  async login(dto: LoginDto) {
    const cred = await this.prisma.credential.findUnique({
      where: { orgId_email: { orgId: dto.orgId, email: dto.email } } as any,
    });
    if (!cred) {
      return {
        ok: false,
        status: 'INVALID_LOGIN',
        error: { code: 'BAD_CREDENTIALS', message: 'Credenciales inválidas' },
      };
    }

    const ok = bcrypt.compareSync(dto.password, cred.passwordHash);
    if (!ok) {
      return {
        ok: false,
        status: 'INVALID_LOGIN',
        error: { code: 'BAD_CREDENTIALS', message: 'Credenciales inválidas' },
      };
    }

    const profile = (cred as any).profile as
      | 'PATIENT'
      | 'CENTER_ADMIN'
      | 'ORG_ADMIN'
      | undefined;
    const name = (cred as any).name ?? '';
    const centerId = (cred as any).centerId ?? null;

    const user = {
      id: cred.userId,
      orgId: cred.orgId,
      email: cred.email,
      patient: profile === 'PATIENT' ? { fullName: name } : null,
      staff: profile !== 'PATIENT' ? { fullName: name, centerId } : null,
      roles: rolesFromProfile(profile).map((k) => ({ role: { key: k } })),
    };

    const payload = this.buildAccessPayload(user);
    const access = await this.signAccess(payload);
    const refresh = await this.signRefresh(user.id, user.orgId);

    return {
      ok: true,
      status: 'LOGGED_IN',
      accessToken: access.token,
      accessTokenExpiresIn: access.expiresIn,
      accessTokenExpiresAt: access.expiresAt,
      refreshToken: refresh.token,
      refreshTokenExpiresIn: refresh.expiresIn,
      refreshTokenExpiresAt: refresh.expiresAt,
      user: payload,
    };
  }

  async refresh(p: { sub: string; orgId: string }) {
    const cred = await this.prisma.credential.findUnique({
      where: { userId: p.sub } as any,
    });
    if (!cred) {
      return {
        ok: false,
        status: 'INVALID_REFRESH',
        error: { code: 'INVALID_SUBJECT', message: 'Token inválido' },
      };
    }

    const profile = (cred as any).profile as
      | 'PATIENT'
      | 'CENTER_ADMIN'
      | 'ORG_ADMIN'
      | undefined;
    const name = (cred as any).name ?? '';
    const centerId = (cred as any).centerId ?? null;

    const user = {
      id: p.sub,
      orgId: p.orgId,
      email: cred.email,
      patient: profile === 'PATIENT' ? { fullName: name } : null,
      staff: profile !== 'PATIENT' ? { fullName: name, centerId } : null,
      roles: rolesFromProfile(profile).map((k) => ({ role: { key: k } })),
    };

    const payload = this.buildAccessPayload(user);
    const access = await this.signAccess(payload);
    return {
      ok: true,
      status: 'REFRESHED',
      accessToken: access.token,
      accessTokenExpiresIn: access.expiresIn,
      accessTokenExpiresAt: access.expiresAt,
      user: payload,
    };
  }
}
