/**
 * Audit Management Routes  —  /api/audits
 *
 * Role permissions:
 *   Admin (SUPER_ADMIN / ORG_ADMIN / SECURITY_OWNER):
 *     - Full CRUD on audits
 *     - Start / close audits
 *     - Update any AuditControl review
 *     - Create / edit / delete findings
 *     - Edit final report draft + sign & complete
 *   AUDITOR:
 *     - GET /                     (only audits where assignedAuditorId = user.id)
 *     - GET /:id                  (only their assigned audit)
 *     - GET /:id/controls         (their assigned audit controls)
 *     - PATCH /:id/controls/:cid  (update review status / notes on their audit)
 *     - POST /:id/findings        (create a finding on their audit)
 *     - PATCH /:id/findings/:fid  (update their findings)
 *     - DELETE /:id/findings/:fid (delete their findings)
 *     - GET/PATCH /:id/report     (edit executive summary on their assigned audit)
 *     - POST /:id/sign-and-complete (sign & lock the audit)
 *
 * Endpoints:
 *   POST   /                          create audit + generate audit_controls  [admin]
 *   GET    /                          list audits (AUDITOR sees only theirs)
 *   GET    /:id                       single audit with controls + findings
 *   PATCH  /:id                       update audit fields                     [admin]
 *   POST   /:id/start                 PLANNED → IN_PROGRESS                   [admin]
 *   POST   /:id/close                 → COMPLETED + snapshot + lock            [admin]
 *   GET    /:id/controls              list AuditControls
 *   PATCH  /:id/controls/:cid         update review status / notes            [admin|auditor]
 *   POST   /:id/findings              create finding                          [admin|auditor]
 *   PATCH  /:id/findings/:fid         update finding                          [admin|auditor]
 *   DELETE /:id/findings/:fid         delete finding                          [admin|auditor]
 *   GET    /:id/report                get final report draft + snapshot data  [admin|auditor]
 *   PATCH  /:id/report                update executiveSummary / auditConclusion / signedPdfUrl  [admin|auditor]
 *   POST   /:id/sign-and-complete     sign + lock + snapshot + → COMPLETED    [admin|auditor]
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';

// ── Role helpers ──────────────────────────────────────────────────────────────

const ADMIN_ROLES   = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];
const AUDITOR_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER', 'AUDITOR'];

function isAdmin(user: any)   { return ADMIN_ROLES.includes(user?.role); }
function canAudit(user: any)  { return AUDITOR_ROLES.includes(user?.role); }
function isAuditor(user: any) { return user?.role === 'AUDITOR'; }

// ── Shared include shapes ─────────────────────────────────────────────────────

const AUDIT_INCLUDE = {
  findings: {
    include: {
      control: { select: { id: true, isoReference: true, title: true } },
    },
    orderBy: { createdAt: 'desc' as const },
  },
  auditControls: {
    include: {
      control: { select: { id: true, isoReference: true, title: true, status: true } },
    },
    orderBy: { control: { isoReference: 'asc' as const } },
  },
} as const;

const CONTROL_DETAIL_INCLUDE = {
  control: {
    include: {
      evidence:     { orderBy: { createdAt: 'desc' as const } },
      riskMappings: { include: { risk: true } },
      testMappings: { include: { test: { select: { id: true, name: true, status: true, type: true, completedAt: true } } } },
      findings:     { orderBy: { createdAt: 'desc' as const } },
    },
  },
} as const;

// ── Validation schemas ────────────────────────────────────────────────────────

const createAuditSchema = z.object({
  name:                 z.string().min(1),
  type:                 z.enum(['INTERNAL', 'EXTERNAL', 'SURVEILLANCE', 'RECERTIFICATION']),
  frameworkName:        z.string().optional(),
  periodStart:          z.string().optional(),
  periodEnd:            z.string().optional(),
  startDate:            z.string(),
  endDate:              z.string().optional(),
  assignedAuditorId:    z.string().uuid().optional(),
  externalAuditorEmail: z.string().email().optional(),
  controlIds:           z.array(z.string().uuid()).optional(),
  allControls:          z.boolean().optional(),
});

const updateAuditSchema = z.object({
  name:                 z.string().min(1).optional(),
  type:                 z.enum(['INTERNAL', 'EXTERNAL', 'SURVEILLANCE', 'RECERTIFICATION']).optional(),
  frameworkName:        z.string().optional(),
  periodStart:          z.string().optional(),
  periodEnd:            z.string().optional(),
  startDate:            z.string().optional(),
  endDate:              z.string().optional(),
  assignedAuditorId:    z.string().uuid().nullable().optional(),
  externalAuditorEmail: z.string().email().nullable().optional(),
});

const updateAuditControlSchema = z.object({
  reviewStatus: z.enum(['PENDING', 'COMPLIANT', 'NON_COMPLIANT', 'NOT_APPLICABLE']).optional(),
  notes:        z.string().optional(),
});

const createFindingSchema = z.object({
  controlId:   z.string().uuid(),
  severity:    z.enum(['MINOR', 'MAJOR', 'OBSERVATION', 'OFI']),
  description: z.string().min(1),
  remediation: z.string().optional(),
  status:      z.enum(['OPEN', 'IN_REMEDIATION', 'READY_FOR_REVIEW', 'CLOSED']).default('OPEN'),
});

const updateFindingSchema = z.object({
  severity:    z.enum(['MINOR', 'MAJOR', 'OBSERVATION', 'OFI']).optional(),
  description: z.string().min(1).optional(),
  remediation: z.string().optional(),
  status:      z.enum(['OPEN', 'IN_REMEDIATION', 'READY_FOR_REVIEW', 'CLOSED']).optional(),
});

// ── Helper: capture metrics snapshot + lock + mark COMPLETED ─────────────────

async function captureSnapshotAndLock(
  auditId: string,
  organizationId: string,
  signedById: string,
): Promise<void> {
  // Load controls + findings for snapshot
  const [controls, findings, risks] = await Promise.all([
    prisma.auditControl.findMany({ where: { auditId } }),
    prisma.auditFinding.findMany({ where: { auditId } }),
    prisma.risk.findMany({ where: { asset: { organizationId } } }),
  ]);

  const eligible   = controls.filter((c: any) => c.reviewStatus !== 'NOT_APPLICABLE');
  const compliant  = controls.filter((c: any) => c.reviewStatus === 'COMPLIANT').length;
  const compliancePct = eligible.length > 0 ? Math.round((compliant / eligible.length) * 100) : 0;

  // Upsert snapshot (idempotent — re-running close is safe)
  await prisma.auditSnapshot.upsert({
    where:  { auditId },
    create: {
      auditId,
      organizationId,
      totalControls:         controls.length,
      compliantControls:     controls.filter((c: any) => c.reviewStatus === 'COMPLIANT').length,
      nonCompliantControls:  controls.filter((c: any) => c.reviewStatus === 'NON_COMPLIANT').length,
      notApplicableControls: controls.filter((c: any) => c.reviewStatus === 'NOT_APPLICABLE').length,
      pendingControls:       controls.filter((c: any) => c.reviewStatus === 'PENDING').length,
      compliancePct,
      totalFindings:         findings.length,
      openFindings:          findings.filter((f: any) => f.status === 'OPEN').length,
      closedFindings:        findings.filter((f: any) => f.status === 'CLOSED').length,
      majorFindings:         findings.filter((f: any) => f.severity === 'MAJOR').length,
      minorFindings:         findings.filter((f: any) => f.severity === 'MINOR').length,
      observationFindings:   findings.filter((f: any) => f.severity === 'OBSERVATION').length,
      ofiFindings:           findings.filter((f: any) => f.severity === 'OFI').length,
      criticalRisks:         risks.filter((r: any) => r.level === 'CRITICAL').length,
      highRisks:             risks.filter((r: any) => r.level === 'HIGH').length,
      mediumRisks:           risks.filter((r: any) => r.level === 'MEDIUM').length,
      lowRisks:              risks.filter((r: any) => r.level === 'LOW').length,
    },
    update: {
      capturedAt:            new Date(),
      totalControls:         controls.length,
      compliantControls:     controls.filter((c: any) => c.reviewStatus === 'COMPLIANT').length,
      nonCompliantControls:  controls.filter((c: any) => c.reviewStatus === 'NON_COMPLIANT').length,
      notApplicableControls: controls.filter((c: any) => c.reviewStatus === 'NOT_APPLICABLE').length,
      pendingControls:       controls.filter((c: any) => c.reviewStatus === 'PENDING').length,
      compliancePct,
      totalFindings:         findings.length,
      openFindings:          findings.filter((f: any) => f.status === 'OPEN').length,
      closedFindings:        findings.filter((f: any) => f.status === 'CLOSED').length,
      majorFindings:         findings.filter((f: any) => f.severity === 'MAJOR').length,
      minorFindings:         findings.filter((f: any) => f.severity === 'MINOR').length,
      observationFindings:   findings.filter((f: any) => f.severity === 'OBSERVATION').length,
      ofiFindings:           findings.filter((f: any) => f.severity === 'OFI').length,
      criticalRisks:         risks.filter((r: any) => r.level === 'CRITICAL').length,
      highRisks:             risks.filter((r: any) => r.level === 'HIGH').length,
      mediumRisks:           risks.filter((r: any) => r.level === 'MEDIUM').length,
      lowRisks:              risks.filter((r: any) => r.level === 'LOW').length,
    },
  });

  // Update audit: COMPLETED + isLocked + signedAt
  await prisma.audit.update({
    where: { id: auditId },
    data: {
      status:    'COMPLETED' as any,
      closedAt:  new Date(),
      isLocked:  true,
      signedAt:  new Date(),
      signedById,
    },
  });
}

// ── Helper: verify audit belongs to org (and optionally to auditor) ───────────

async function getAuditOrFail(
  id: string,
  user: any,
  reply: FastifyReply,
): Promise<any | null> {
  const where: any = { id, organizationId: user.organizationId };
  // AUDITOR can only access audits assigned to them
  if (isAuditor(user)) where.assignedAuditorId = user.id;

  const audit = await prisma.audit.findFirst({ where });
  if (!audit) {
    reply.status(404).send({ error: 'Audit not found' });
    return null;
  }
  return audit;
}

// ── Routes ────────────────────────────────────────────────────────────────────

export async function auditRoutes(app: FastifyInstance) {

  // ── POST / — create audit ──────────────────────────────────────────────────
  app.post('/', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const body = createAuditSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const {
      name, type, frameworkName, periodStart, periodEnd,
      startDate, endDate, assignedAuditorId, externalAuditorEmail,
      controlIds, allControls,
    } = body.data;

    let scopedControlIds: string[] = [];
    if (allControls || (!controlIds || controlIds.length === 0)) {
      const controls = await prisma.control.findMany({
        where: { organizationId: user.organizationId },
        select: { id: true },
      });
      scopedControlIds = controls.map((c: { id: string }) => c.id);
    } else {
      const controls = await prisma.control.findMany({
        where: { id: { in: controlIds }, organizationId: user.organizationId },
        select: { id: true },
      });
      scopedControlIds = controls.map((c: { id: string }) => c.id);
    }

    const audit = await prisma.audit.create({
      data: {
        name,
        type:                 type as any,
        frameworkName,
        periodStart:          periodStart ? new Date(periodStart) : undefined,
        periodEnd:            periodEnd   ? new Date(periodEnd)   : undefined,
        startDate:            new Date(startDate),
        endDate:              endDate     ? new Date(endDate)     : undefined,
        status:               'PLANNED',
        assignedAuditorId,
        externalAuditorEmail,
        ownerId:              user.id,
        organizationId:       user.organizationId,
        auditControls: {
          create: scopedControlIds.map((cid: string) => ({ controlId: cid })),
        },
      },
      include: AUDIT_INCLUDE,
    });

    return reply.status(201).send({ success: true, data: audit });
  });

  // ── GET / — list audits ────────────────────────────────────────────────────
  app.get('/', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const { type, status, search } = request.query as Record<string, string>;

    const where: any = { organizationId: user.organizationId };
    // AUDITOR sees only their assigned audits
    if (isAuditor(user)) where.assignedAuditorId = user.id;

    if (type)   where.type   = type;
    if (status) where.status = status;
    if (search) {
      where.OR = [
        { name:          { contains: search, mode: 'insensitive' } },
        { frameworkName: { contains: search, mode: 'insensitive' } },
      ];
    }

    const audits = await prisma.audit.findMany({
      where,
      include: {
        findings: { select: { id: true, severity: true, status: true } },
        _count:   { select: { auditControls: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    return reply.send({ success: true, data: audits });
  });

  // ── GET /:id — single audit ────────────────────────────────────────────────
  app.get('/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user  = (request as any).user;
    const { id } = request.params as { id: string };

    const where: any = { id, organizationId: user.organizationId };
    if (isAuditor(user)) where.assignedAuditorId = user.id;

    const audit = await prisma.audit.findFirst({ where, include: AUDIT_INCLUDE });
    if (!audit) return reply.status(404).send({ error: 'Audit not found' });
    return reply.send({ success: true, data: audit });
  });

  // ── PATCH /:id — update audit metadata ────────────────────────────────────
  app.patch('/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const { id } = request.params as { id: string };
    const body = updateAuditSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const existing = await prisma.audit.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });

    const { periodStart, periodEnd, startDate, endDate, ...rest } = body.data;

    const audit = await prisma.audit.update({
      where: { id },
      data: {
        ...rest,
        ...(periodStart !== undefined ? { periodStart: periodStart ? new Date(periodStart) : null } : {}),
        ...(periodEnd   !== undefined ? { periodEnd:   periodEnd   ? new Date(periodEnd)   : null } : {}),
        ...(startDate   !== undefined ? { startDate:   new Date(startDate) } : {}),
        ...(endDate     !== undefined ? { endDate:     endDate     ? new Date(endDate)     : null } : {}),
      },
      include: AUDIT_INCLUDE,
    });

    return reply.send({ success: true, data: audit });
  });

  // ── POST /:id/start ────────────────────────────────────────────────────────
  app.post('/:id/start', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const { id } = request.params as { id: string };
    const existing = await prisma.audit.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });
    if (!['DRAFT', 'PLANNED'].includes(existing.status as string))
      return reply.status(400).send({ error: `Cannot start an audit with status ${existing.status}` });

    const audit = await prisma.audit.update({
      where: { id },
      data:  { status: 'IN_PROGRESS' },
      include: AUDIT_INCLUDE,
    });
    return reply.send({ success: true, data: audit });
  });

  // ── POST /:id/close ───────────────────────────────────────────────────────
  // Admin shortcut to mark COMPLETED without going through sign-and-complete.
  // Also captures snapshot + locks.
  app.post('/:id/close', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const { id } = request.params as { id: string };
    const existing = await prisma.audit.findFirst({
      where:   { id, organizationId: user.organizationId },
      include: { auditControls: true, findings: true },
    });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });
    if ((existing as any).status === 'COMPLETED')
      return reply.status(400).send({ error: 'Audit is already completed' });

    await captureSnapshotAndLock(id, user.organizationId, user.id);

    const audit = await prisma.audit.findFirst({ where: { id }, include: AUDIT_INCLUDE });
    return reply.send({ success: true, data: audit });
  });

  // ── GET /:id/report — get final report draft + snapshot ───────────────────
  app.get('/:id/report', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user   = (request as any).user;
    const { id } = request.params as { id: string };

    if (!canAudit(user)) return reply.status(403).send({ error: 'Forbidden' });

    const where: any = { id, organizationId: user.organizationId };
    if (isAuditor(user)) where.assignedAuditorId = user.id;

    const audit = await prisma.audit.findFirst({
      where,
      include: {
        ...AUDIT_INCLUDE,
        snapshot: true,
        auditControls: {
          include: {
            control: { select: { id: true, isoReference: true, title: true, status: true } },
          },
          orderBy: { control: { isoReference: 'asc' as const } },
        },
      },
    });
    if (!audit) return reply.status(404).send({ error: 'Audit not found' });

    // Auto-generate a live metrics block (used before snapshot exists)
    const controls = (audit as any).auditControls as any[];
    const findings = (audit as any).findings as any[];

    const metrics = {
      totalControls:        controls.length,
      compliantControls:    controls.filter((c: any) => c.reviewStatus === 'COMPLIANT').length,
      nonCompliantControls: controls.filter((c: any) => c.reviewStatus === 'NON_COMPLIANT').length,
      notApplicableControls: controls.filter((c: any) => c.reviewStatus === 'NOT_APPLICABLE').length,
      pendingControls:      controls.filter((c: any) => c.reviewStatus === 'PENDING').length,
      compliancePct:        (() => {
        const eligible = controls.filter((c: any) => c.reviewStatus !== 'NOT_APPLICABLE');
        const compliant = controls.filter((c: any) => c.reviewStatus === 'COMPLIANT').length;
        return eligible.length > 0 ? Math.round((compliant / eligible.length) * 100) : 0;
      })(),
      totalFindings:       findings.length,
      openFindings:        findings.filter((f: any) => f.status === 'OPEN').length,
      closedFindings:      findings.filter((f: any) => f.status === 'CLOSED').length,
      majorFindings:       findings.filter((f: any) => f.severity === 'MAJOR').length,
      minorFindings:       findings.filter((f: any) => f.severity === 'MINOR').length,
      observationFindings: findings.filter((f: any) => f.severity === 'OBSERVATION').length,
      ofiFindings:         findings.filter((f: any) => f.severity === 'OFI').length,
    };

    return reply.send({ success: true, data: { audit, metrics } });
  });

  // ── PATCH /:id/report — update executive summary / conclusion / PDF ────────
  app.patch('/:id/report', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user   = (request as any).user;
    const { id } = request.params as { id: string };

    if (!canAudit(user)) return reply.status(403).send({ error: 'Forbidden' });

    const where: any = { id, organizationId: user.organizationId };
    if (isAuditor(user)) where.assignedAuditorId = user.id;

    const existing = await prisma.audit.findFirst({ where });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });
    if ((existing as any).isLocked)
      return reply.status(400).send({ error: 'Audit is locked after completion' });

    const body = request.body as any;
    const updateData: any = {};
    if (body.executiveSummary  !== undefined) updateData.executiveSummary  = body.executiveSummary;
    if (body.auditConclusion   !== undefined) updateData.auditConclusion   = body.auditConclusion;
    if (body.signedPdfUrl      !== undefined) updateData.signedPdfUrl      = body.signedPdfUrl;

    const updated = await prisma.audit.update({ where: { id }, data: updateData });
    return reply.send({ success: true, data: updated });
  });

  // ── POST /:id/sign-and-complete — sign, snapshot, lock, → COMPLETED ────────
  app.post('/:id/sign-and-complete', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user   = (request as any).user;
    const { id } = request.params as { id: string };

    if (!canAudit(user)) return reply.status(403).send({ error: 'Forbidden' });

    const where: any = { id, organizationId: user.organizationId };
    if (isAuditor(user)) where.assignedAuditorId = user.id;

    const existing = await prisma.audit.findFirst({ where });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });
    if ((existing as any).isLocked)
      return reply.status(400).send({ error: 'Audit is already signed and locked' });
    if ((existing as any).status === 'COMPLETED')
      return reply.status(400).send({ error: 'Audit is already completed' });

    await captureSnapshotAndLock(id, user.organizationId, user.id);

    const audit = await prisma.audit.findFirst({ where: { id }, include: AUDIT_INCLUDE });
    return reply.send({ success: true, data: audit });
  });

  // ── GET /:id/controls ─────────────────────────────────────────────────────
  app.get('/:id/controls', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const { id } = request.params as { id: string };

    const audit = await getAuditOrFail(id, user, reply);
    if (!audit) return;

    const controls = await prisma.auditControl.findMany({
      where: { auditId: id },
      include: CONTROL_DETAIL_INCLUDE,
      orderBy: { control: { isoReference: 'asc' } },
    });

    return reply.send({ success: true, data: controls });
  });

  // ── PATCH /:id/controls/:cid — update AuditControl review ─────────────────
  app.patch('/:id/controls/:cid', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!canAudit(user)) return reply.status(403).send({ error: 'Auditor access required' });

    const { id, cid } = request.params as { id: string; cid: string };
    const body = updateAuditControlSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const audit = await getAuditOrFail(id, user, reply);
    if (!audit) return;

    if (audit.isLocked) return reply.status(400).send({ error: 'Audit is locked and cannot be modified' });

    const updated = await prisma.auditControl.update({
      where: { id: cid },
      data: {
        ...body.data,
        ...(body.data.reviewStatus && body.data.reviewStatus !== 'PENDING'
          ? { reviewedBy: user.id, reviewedAt: new Date() }
          : {}),
      },
      include: {
        control: { select: { id: true, isoReference: true, title: true, status: true } },
      },
    });

    return reply.send({ success: true, data: updated });
  });

  // ── POST /:id/findings — create finding ──────────────────────────────────
  app.post('/:id/findings', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!canAudit(user)) return reply.status(403).send({ error: 'Auditor access required' });

    const { id } = request.params as { id: string };
    const body = createFindingSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const audit = await getAuditOrFail(id, user, reply);
    if (!audit) return;
    if (audit.isLocked) return reply.status(400).send({ error: 'Audit is locked and cannot be modified' });

    // Verify the control is in scope for this audit
    const inScope = await prisma.auditControl.findFirst({
      where: { auditId: id, controlId: body.data.controlId },
    });
    if (!inScope) return reply.status(400).send({ error: 'Control is not in scope for this audit' });

    const finding = await prisma.auditFinding.create({
      data: {
        auditId:        id,
        controlId:      body.data.controlId,
        organizationId: user.organizationId,
        severity:       body.data.severity as any,
        description:    body.data.description,
        remediationPlan: body.data.remediation,
        status:         body.data.status as any,
      },
      include: {
        control: { select: { id: true, isoReference: true, title: true } },
      },
    });

    return reply.status(201).send({ success: true, data: finding });
  });

  // ── PATCH /:id/findings/:fid — update finding ─────────────────────────────
  app.patch('/:id/findings/:fid', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!canAudit(user)) return reply.status(403).send({ error: 'Auditor access required' });

    const { id, fid } = request.params as { id: string; fid: string };
    const body = updateFindingSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const audit = await getAuditOrFail(id, user, reply);
    if (!audit) return;
    if (audit.isLocked) return reply.status(400).send({ error: 'Audit is locked and cannot be modified' });

    const finding = await prisma.auditFinding.findFirst({ where: { id: fid, auditId: id } });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    const updateData: any = {};
    if (body.data.severity    !== undefined) updateData.severity        = body.data.severity;
    if (body.data.description !== undefined) updateData.description     = body.data.description;
    if (body.data.remediation !== undefined) updateData.remediationPlan = body.data.remediation;
    if (body.data.status      !== undefined) updateData.status          = body.data.status;

    const updated = await prisma.auditFinding.update({
      where: { id: fid },
      data:  updateData,
      include: { control: { select: { id: true, isoReference: true, title: true } } },
    });

    return reply.send({ success: true, data: updated });
  });

  // ── DELETE /:id/findings/:fid — delete finding ────────────────────────────
  app.delete('/:id/findings/:fid', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!canAudit(user)) return reply.status(403).send({ error: 'Auditor access required' });

    const { id, fid } = request.params as { id: string; fid: string };

    const audit = await getAuditOrFail(id, user, reply);
    if (!audit) return;
    if (audit.isLocked) return reply.status(400).send({ error: 'Audit is locked and cannot be modified' });

    const finding = await prisma.auditFinding.findFirst({ where: { id: fid, auditId: id } });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    await prisma.auditFinding.delete({ where: { id: fid } });
    return reply.send({ success: true });
  });
}
