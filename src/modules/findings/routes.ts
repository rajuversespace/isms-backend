/**
 * Findings & Remediation Routes  —  /api/findings
 *
 * Workflow:  OPEN → IN_REMEDIATION → READY_FOR_REVIEW → CLOSED
 *            Auditor can reject READY_FOR_REVIEW → OPEN
 *
 * Endpoints:
 *   GET    /                          list findings (org-scoped, filters)
 *   GET    /my-tasks                  findings assigned to current user
 *   GET    /:id                       single finding detail
 *   POST   /                          create finding  [admin|auditor]
 *   PATCH  /:id                       update plan/dueDate/assignedTo  [admin|auditor]
 *   POST   /:id/start-remediation     OPEN → IN_REMEDIATION  (assignee or admin)
 *   POST   /:id/submit-review         IN_REMEDIATION → READY_FOR_REVIEW  (assignee)
 *   POST   /:id/accept                READY_FOR_REVIEW → CLOSED  [admin|auditor]
 *   POST   /:id/reject                READY_FOR_REVIEW → OPEN    [admin|auditor]
 *   POST   /:id/evidence              attach evidence URL
 */

import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';

// ── Role helpers ──────────────────────────────────────────────────────────────

const ADMIN_ROLES   = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];
const AUDITOR_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER', 'AUDITOR'];

function isAdmin(user: any)   { return ADMIN_ROLES.includes(user?.role); }
function canAudit(user: any)  { return AUDITOR_ROLES.includes(user?.role); }

// ── Include shape ─────────────────────────────────────────────────────────────

const FINDING_INCLUDE = {
  control: { select: { id: true, isoReference: true, title: true } },
  audit:   { select: { id: true, name: true, type: true } },
  assignee: { select: { id: true, name: true, email: true } },
} as const;

// ── Validation schemas ────────────────────────────────────────────────────────

const CreateFindingSchema = z.object({
  auditId:         z.string().uuid(),
  controlId:       z.string().uuid(),
  severity:        z.enum(['MINOR', 'MAJOR', 'OBSERVATION', 'OFI']),
  description:     z.string().min(1),
  remediationPlan: z.string().optional(),
  dueDate:         z.string().datetime({ offset: true }).optional(),
  assignedTo:      z.string().uuid().optional(),
});

const UpdateFindingSchema = z.object({
  remediationPlan: z.string().optional(),
  dueDate:         z.string().datetime({ offset: true }).optional().nullable(),
  assignedTo:      z.string().uuid().optional().nullable(),
  severity:        z.enum(['MINOR', 'MAJOR', 'OBSERVATION', 'OFI']).optional(),
  description:     z.string().min(1).optional(),
});

// ── Route plugin ──────────────────────────────────────────────────────────────

export async function findingRoutes(app: FastifyInstance) {

  // ── GET / — list findings (org-scoped with optional filters) ─────────────
  app.get('/', { preHandler: [authenticate] }, async (req, reply) => {
    const user = (req as any).user;
    const query = req.query as Record<string, string>;

    const where: any = { organizationId: user.organizationId };

    if (query.severity)  where.severity  = query.severity;
    if (query.status)    where.status    = query.status;
    if (query.controlId) where.controlId = query.controlId;
    if (query.auditId)   where.auditId   = query.auditId;

    if (query.overdue === 'true') {
      where.dueDate = { lt: new Date() };
      where.status  = { notIn: ['CLOSED'] };
    }

    const findings = await prisma.auditFinding.findMany({
      where,
      include: FINDING_INCLUDE,
      orderBy: { createdAt: 'desc' },
    });

    return findings;
  });

  // ── GET /my-tasks — findings assigned to current user ────────────────────
  app.get('/my-tasks', { preHandler: [authenticate] }, async (req, reply) => {
    const user = (req as any).user;

    const findings = await prisma.auditFinding.findMany({
      where: {
        assignedTo:     user.id,
        organizationId: user.organizationId,
        status:         { notIn: ['CLOSED'] },
      },
      include: FINDING_INCLUDE,
      orderBy: [
        { dueDate: 'asc' },
        { createdAt: 'desc' },
      ],
    });

    return findings;
  });

  // ── GET /:id — single finding ─────────────────────────────────────────────
  app.get('/:id', { preHandler: [authenticate] }, async (req, reply) => {
    const user     = (req as any).user;
    const { id }   = req.params as { id: string };

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
      include: FINDING_INCLUDE,
    });

    if (!finding) return reply.status(404).send({ error: 'Finding not found' });
    return finding;
  });

  // ── POST / — create finding  [admin|auditor] ──────────────────────────────
  app.post('/', { preHandler: [authenticate] }, async (req, reply) => {
    const user = (req as any).user;

    if (!canAudit(user)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const parsed = CreateFindingSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation error', details: parsed.error.flatten() });
    }

    const { auditId, controlId, severity, description, remediationPlan, dueDate, assignedTo } = parsed.data;

    // Verify the audit belongs to this org
    const audit = await prisma.audit.findFirst({
      where: { id: auditId, organizationId: user.organizationId },
    });
    if (!audit) return reply.status(404).send({ error: 'Audit not found' });

    const finding = await prisma.auditFinding.create({
      data: {
        auditId,
        controlId,
        organizationId: user.organizationId,
        severity:        severity as any,
        status:          'OPEN' as any,
        description,
        remediationPlan: remediationPlan ?? null,
        dueDate:         dueDate ? new Date(dueDate) : null,
        assignedTo:      assignedTo ?? null,
      },
      include: FINDING_INCLUDE,
    });

    return reply.status(201).send(finding);
  });

  // ── PATCH /:id — update plan / dueDate / assignedTo  [admin|auditor] ─────
  app.patch('/:id', { preHandler: [authenticate] }, async (req, reply) => {
    const user   = (req as any).user;
    const { id } = req.params as { id: string };

    if (!canAudit(user)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    const parsed = UpdateFindingSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Validation error', details: parsed.error.flatten() });
    }

    const data: any = {};
    if (parsed.data.remediationPlan !== undefined) data.remediationPlan = parsed.data.remediationPlan;
    if (parsed.data.dueDate         !== undefined) data.dueDate         = parsed.data.dueDate ? new Date(parsed.data.dueDate) : null;
    if (parsed.data.assignedTo      !== undefined) data.assignedTo      = parsed.data.assignedTo;
    if (parsed.data.severity        !== undefined) data.severity        = parsed.data.severity;
    if (parsed.data.description     !== undefined) data.description     = parsed.data.description;

    const updated = await prisma.auditFinding.update({
      where: { id },
      data,
      include: FINDING_INCLUDE,
    });

    return updated;
  });

  // ── POST /:id/start-remediation — OPEN → IN_REMEDIATION ──────────────────
  app.post('/:id/start-remediation', { preHandler: [authenticate] }, async (req, reply) => {
    const user   = (req as any).user;
    const { id } = req.params as { id: string };

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    // Only the assigned user or an admin can start remediation
    const isAssignee = finding.assignedTo === user.id;
    if (!isAssignee && !isAdmin(user)) {
      return reply.status(403).send({ error: 'Only the assigned user or an admin can start remediation' });
    }

    if (finding.status !== 'OPEN') {
      return reply.status(400).send({ error: `Finding must be OPEN to start remediation (current: ${finding.status})` });
    }

    const updated = await prisma.auditFinding.update({
      where: { id },
      data:  { status: 'IN_REMEDIATION' as any },
      include: FINDING_INCLUDE,
    });

    return updated;
  });

  // ── POST /:id/submit-review — IN_REMEDIATION → READY_FOR_REVIEW ──────────
  app.post('/:id/submit-review', { preHandler: [authenticate] }, async (req, reply) => {
    const user   = (req as any).user;
    const { id } = req.params as { id: string };

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    const isAssignee = finding.assignedTo === user.id;
    if (!isAssignee && !isAdmin(user)) {
      return reply.status(403).send({ error: 'Only the assigned user or an admin can submit for review' });
    }

    if (finding.status !== 'IN_REMEDIATION') {
      return reply.status(400).send({ error: `Finding must be IN_REMEDIATION to submit for review (current: ${finding.status})` });
    }

    const updated = await prisma.auditFinding.update({
      where: { id },
      data:  { status: 'READY_FOR_REVIEW' as any },
      include: FINDING_INCLUDE,
    });

    return updated;
  });

  // ── POST /:id/accept — READY_FOR_REVIEW → CLOSED  [admin|auditor] ────────
  app.post('/:id/accept', { preHandler: [authenticate] }, async (req, reply) => {
    const user   = (req as any).user;
    const { id } = req.params as { id: string };

    if (!canAudit(user)) {
      return reply.status(403).send({ error: 'Only auditors/admins can accept findings' });
    }

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    if (finding.status !== 'READY_FOR_REVIEW') {
      return reply.status(400).send({ error: `Finding must be READY_FOR_REVIEW to accept (current: ${finding.status})` });
    }

    const updated = await prisma.auditFinding.update({
      where: { id },
      data:  { status: 'CLOSED' as any, closedAt: new Date() },
      include: FINDING_INCLUDE,
    });

    return updated;
  });

  // ── POST /:id/reject — READY_FOR_REVIEW → OPEN  [admin|auditor] ──────────
  app.post('/:id/reject', { preHandler: [authenticate] }, async (req, reply) => {
    const user   = (req as any).user;
    const { id } = req.params as { id: string };

    if (!canAudit(user)) {
      return reply.status(403).send({ error: 'Only auditors/admins can reject findings' });
    }

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    if (finding.status !== 'READY_FOR_REVIEW') {
      return reply.status(400).send({ error: `Finding must be READY_FOR_REVIEW to reject (current: ${finding.status})` });
    }

    const updated = await prisma.auditFinding.update({
      where: { id },
      data:  { status: 'OPEN' as any, closedAt: null },
      include: FINDING_INCLUDE,
    });

    return updated;
  });

  // ── POST /:id/evidence — attach evidence URL ──────────────────────────────
  app.post('/:id/evidence', { preHandler: [authenticate] }, async (req, reply) => {
    const user   = (req as any).user;
    const { id } = req.params as { id: string };

    const finding = await prisma.auditFinding.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    const isAssignee = finding.assignedTo === user.id;
    if (!isAssignee && !canAudit(user)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const body = req.body as any;
    const evidenceUrl = body?.evidenceUrl;
    if (!evidenceUrl || typeof evidenceUrl !== 'string') {
      return reply.status(400).send({ error: 'evidenceUrl is required' });
    }

    const updated = await prisma.auditFinding.update({
      where: { id },
      data:  { evidenceUrl },
      include: FINDING_INCLUDE,
    });

    return updated;
  });
}
