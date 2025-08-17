export class RegisterDto {
  email: string; password: string; orgId: string;
  profileType: 'PATIENT'|'CENTER_ADMIN'|'ORG_ADMIN';
  fullName?: string; document?: string; phone?: string;
  staffFullName?: string; centerId?: string;
}
export class LoginDto { email: string; password: string; orgId: string; }
