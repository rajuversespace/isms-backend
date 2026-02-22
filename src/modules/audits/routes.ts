/**
 * Audit Management Routes  —  /api/audits
 *
 * Endpoints:
 *   POST   /                   create audit + generate audit_controls
 *   GET    /                   list audits (filters: type, status, search)
 *   GET    /:id                single audit with controls + findings
 *   PATCH  /:id                update audit fields
 *   POST   /:id/start          Draft/Planned → In Progress
 *   POST   /:id/close          In Progress → Completed
 *   GET    /:id/controls       list AuditControls for an audit
 *   PATCH  /:id/controls/:cid  update a single AuditControl review status / notes
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';

// ── Helpers ───────────────────────────────────────────────────────────────────

const ADMIN_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];

function isAdmin(user: any) {
  return ADMIN_ROLES.includes(user?.role);
}

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

// ── Validation schemas ────────────────────────────────────────────────────────

const createAuditSchema = z.object({
  name:                 z.string().min(1),
  type:                 z.enum(['INTERNAL', 'EXTERNAL', 'SURVEILLANCE', 'RECERTIFICATION']),
  frameworkName:        z.string().optional(),
  periodStart:          z.string().optional(),   // ISO date string
  periodEnd:            z.string().optional(),
  startDate:            z.string(),              // required
  endDate:              z.string().optional(),
  assignedAuditorId:    z.string().uuid().optional(),
  externalAuditorEmail: z.string().email().optional(),
  // scope: either entire framework (empty/omitted controlIds) or specific control ids
  controlIds:           z.array(z.string().uuid()).optional(),
  allControls:          z.boolean().optional(),  // true = scope entire org's controls
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
  reviewStatus: z.enum(['PENDING', 'REVIEWED', 'FLAGGED', 'NOT_APPLICABLE']).optional(),
  notes:        z.string().optional(),
});

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

    // Determine which controls to scope
    let scopedControlIds: string[] = [];

    if (allControls || (!controlIds || controlIds.length === 0)) {
      // Entire org's controls
      const controls = await prisma.control.findMany({
        where: { organizationId: user.organizationId },
        select: { id: true },
      });
      scopedControlIds = controls.map((c: { id: string }) => c.id);
    } else {
      // Verify all supplied controlIds belong to this org
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

    const audit = await prisma.audit.findFirst({
      where: { id, organizationId: user.organizationId },
      include: AUDIT_INCLUDE,
    });

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

  // ── POST /:id/start — move to In Progress ─────────────────────────────────
  app.post('/:id/start', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const { id } = request.params as { id: string };
    const existing = await prisma.audit.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });
    if (!['DRAFT', 'PLANNED'].includes(existing.status)) {
      return reply.status(400).send({ error: `Cannot start an audit with status ${existing.status}` });
    }

    const audit = await prisma.audit.update({
      where: { id },
      data:  { status: 'IN_PROGRESS' },
      include: AUDIT_INCLUDE,
    });

    return reply.send({ success: true, data: audit });
  });

  // ── POST /:id/close — move to Completed ───────────────────────────────────
  app.post('/:id/close', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const { id } = request.params as { id: string };
    const existing = await prisma.audit.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Audit not found' });
    if (existing.status === 'COMPLETED') {
      return reply.status(400).send({ error: 'Audit is already completed' });
    }

    const audit = await prisma.audit.update({
      where: { id },
      data:  { status: 'COMPLETED', closedAt: new Date() },
      include: AUDIT_INCLUDE,
    });

    return reply.send({ success: true, data: audit });
  });

  // ── GET /:id/controls — list audit controls ────────────────────────────────
  app.get('/:id/controls', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const { id } = request.params as { id: string };

    const audit = await prisma.audit.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!audit) return reply.status(404).send({ error: 'Audit not found' });

    const controls = await prisma.auditControl.findMany({
      where: { auditId: id },
      include: {
        control: { select: { id: true, isoReference: true, title: true, status: true, description: true } },
      },
      orderBy: { control: { isoReference: 'asc' } },
    });

    return reply.send({ success: true, data: controls });
  });

  // ── PATCH /:id/controls/:cid — update AuditControl review ─────────────────
  app.patch('/:id/controls/:cid', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const { id, cid } = request.params as { id: string; cid: string };
    const body = updateAuditControlSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    // Verify the audit belongs to this org
    const audit = await prisma.audit.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!audit) return reply.status(404).send({ error: 'Audit not found' });

    const updated = await prisma.auditControl.update({
      where: { id: cid },
      data: {
        ...body.data,
        ...(body.data.reviewStatus === 'REVIEWED' ? { reviewedBy: user.id, reviewedAt: new Date() } : {}),
      },
      include: {
        control: { select: { id: true, isoReference: true, title: true, status: true } },
      },
    });

    return reply.send({ success: true, data: updated });
  });
}
