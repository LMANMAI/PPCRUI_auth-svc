import { Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";
import { RegisterDto, LoginDto } from "./dto/auth.dto";
import * as bcrypt from "bcryptjs";

type ProfileKey =
  | "PATIENT"
  | "CENTER_ADMIN"
  | "ORG_ADMIN"
  | "OPERADOR_SALUD"
  | "PERSONAL_SALUD";

function rolesFromProfile(p?: ProfileKey): string[] {
  if (p === "ORG_ADMIN") return ["ORG_ADMIN"];
  if (p === "CENTER_ADMIN") return ["CENTER_ADMIN"];
  return [];
}

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaClient
  ) {}

  private buildAccessPayload(user: any) {
    const roles: string[] = (user.roles ?? []).map(
      (r: any) => r?.role?.key ?? r
    );
    const name = user.patient?.fullName ?? user.staff?.fullName ?? "";
    const profile: ProfileKey =
      user.profile ??
      (user.patient
        ? "PATIENT"
        : roles.includes("ORG_ADMIN")
        ? "ORG_ADMIN"
        : roles.includes("CENTER_ADMIN")
        ? "CENTER_ADMIN"
        : "PATIENT");
    const centerId = user.staff?.centerId ?? null;

    return {
      sub: user.id,
      orgId: user.orgId,
      email: user.email,
      name,
      profile,
      centerId,
      roles,
      phone: user.phone ?? null,
      usuarioVerificado: !!user.usuarioVerificado,
      jti: randomUUID(),
    };
  }

  private getAccessTtlSeconds(profile: ProfileKey): number | null {
    const admin = Number(process.env.ADMIN_ACCESS_TTL_SEC ?? 7200);
    const patient = Number(process.env.PATIENT_ACCESS_TTL_SEC ?? 0);
    return profile === "ORG_ADMIN" || profile === "CENTER_ADMIN"
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
      ttl ? { expiresIn: ttl } : {}
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
      { sub: userId, orgId, typ: "refresh", jti: randomUUID() },
      { expiresIn: ttl }
    );
    return {
      token,
      expiresIn: ttl,
      expiresAt: new Date((now + ttl) * 1000).toISOString(),
    };
  }

  async register(dto: RegisterDto) {
    const email = dto.email.trim().toLowerCase();
    const document = (dto as any).document?.trim?.() ?? "";
    const phone = (dto as any).phone ?? null;

    const [byEmail, byDoc] = await this.prisma.$transaction([
      this.prisma.credential.findUnique({
        where: { orgId_email: { orgId: dto.orgId, email } } as any,
      }),
      this.prisma.credential.findUnique({
        where: { orgId_dni: { orgId: dto.orgId, dni: document } } as any,
      }),
    ]);

    if (byEmail) {
      return {
        ok: false,
        status: "ALREADY_REGISTERED",
        error: {
          code: "EMAIL_EXISTS",
          message:
            "Ya existe una cuenta registrada con ese email para esta organización.",
        },
      };
    }
    if (byDoc) {
      return {
        ok: false,
        status: "ALREADY_REGISTERED",
        error: {
          code: "DNI_EXISTS",
          message:
            "Ya existe una cuenta registrada con ese documento para esta organización.",
        },
      };
    }

    const created = {
      id: randomUUID(),
      orgId: dto.orgId,
      email,
      profile: dto.profileType as ProfileKey,
      patient:
        dto.profileType === "PATIENT" ? { fullName: dto.fullName ?? "" } : null,
      staff:
        dto.profileType !== "PATIENT"
          ? {
              fullName: dto.staffFullName ?? dto.fullName ?? "",
              centerId: dto.centerId ?? null,
            }
          : null,
      roles: rolesFromProfile(dto.profileType as ProfileKey).map((k) => ({
        role: { key: k },
      })),
      phone,
      usuarioVerificado: false,
    };

    const hash = bcrypt.hashSync(dto.password, 10);
    await this.prisma.credential.create({
      data: {
        orgId: created.orgId,
        userId: created.id,
        email: created.email,
        dni: document,
        telefono: phone,
        usuarioVerificado: false,
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
      status: "CREATED",
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
    const identifier =
      (dto as any).identifier?.trim?.() ?? (dto as any).email?.trim?.() ?? "";

    if (!identifier) {
      return {
        ok: false,
        status: "INVALID_LOGIN",
        error: { code: "MISSING_IDENTIFIER", message: "Falta email o DNI." },
      };
    }

    const isEmail = identifier.includes("@");
    const normalizedEmail = isEmail ? identifier.toLowerCase() : null;

    const cred = await this.prisma.credential.findFirst({
      where: {
        orgId: dto.orgId,
        OR: [
          ...(normalizedEmail ? [{ email: normalizedEmail }] : []),
          { dni: identifier },
        ],
      } as any,
    });

    if (!cred) {
      return {
        ok: false,
        status: "INVALID_LOGIN",
        error: { code: "BAD_CREDENTIALS", message: "Credenciales inválidas" },
      };
    }

    const ok = bcrypt.compareSync(dto.password, cred.passwordHash);
    if (!ok) {
      return {
        ok: false,
        status: "INVALID_LOGIN",
        error: { code: "BAD_CREDENTIALS", message: "Credenciales inválidas" },
      };
    }

    const profile = (cred as any).profile as ProfileKey;
    const name = (cred as any).name ?? "";
    const centerId = (cred as any).centerId ?? null;

    const user = {
      id: cred.userId,
      orgId: cred.orgId,
      email: cred.email,
      profile,
      patient: profile === "PATIENT" ? { fullName: name } : null,
      staff: profile !== "PATIENT" ? { fullName: name, centerId } : null,
      roles: rolesFromProfile(profile).map((k) => ({ role: { key: k } })),
      phone: (cred as any).telefono ?? null,

      usuarioVerificado: !!(cred as any).usuarioVerificado,
    };

    const payload = this.buildAccessPayload(user);
    const access = await this.signAccess(payload);
    const refresh = await this.signRefresh(user.id, user.orgId);

    return {
      ok: true,
      status: "LOGGED_IN",
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
    const cred = await this.prisma.credential.findFirst({
      where: { userId: p.sub } as any,
    });
    if (!cred) {
      return {
        ok: false,
        status: "INVALID_REFRESH",
        error: { code: "INVALID_SUBJECT", message: "Token inválido" },
      };
    }

    const profile = (cred as any).profile as ProfileKey;
    const name = (cred as any).name ?? "";
    const centerId = (cred as any).centerId ?? null;

    const user = {
      id: p.sub,
      orgId: p.orgId,
      email: cred.email,
      profile,
      patient: profile === "PATIENT" ? { fullName: name } : null,
      staff: profile !== "PATIENT" ? { fullName: name, centerId } : null,
      roles: rolesFromProfile(profile).map((k) => ({ role: { key: k } })),
      phone: (cred as any).telefono ?? null,
      usuarioVerificado: !!(cred as any).usuarioVerificado,
    };

    const payload = this.buildAccessPayload(user);
    const access = await this.signAccess(payload);
    return {
      ok: true,
      status: "REFRESHED",
      accessToken: access.token,
      accessTokenExpiresIn: access.expiresIn,
      accessTokenExpiresAt: access.expiresAt,
      user: payload,
    };
  }
}
