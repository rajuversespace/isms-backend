/**
 * Trust Center Routes
 *
 * Admin (auth-required):
 *   GET    /api/trust/settings                    — get or create settings for org
 *   PUT    /api/trust/settings                    — upsert settings
 *   GET    /api/trust/documents                   — list documents
 *   POST   /api/trust/documents                   — create document
 *   PATCH  /api/trust/documents/:id               — update document
 *   DELETE /api/trust/documents/:id               — delete document
 *   GET    /api/trust/access-requests             — list access requests
 *   PATCH  /api/trust/access-requests/:id         — approve / reject
 *   GET    /api/trust/announcements               — list announcements
 *   POST   /api/trust/announcements               — create announcement
 *   PATCH  /api/trust/announcements/:id           — update announcement
 *   DELETE /api/trust/announcements/:id           — delete announcement
 *   GET    /api/trust/questionnaire-requests      — list questionnaire requests
 *   PATCH  /api/trust/questionnaire-requests/:id  — update (attach response file)
 *   POST   /api/trust/metrics/snapshot            — manually trigger snapshot
 *
 * Public (no auth):
 *   GET    /api/trust/public/:orgSlug             — public portal data
 *   POST   /api/trust/public/:orgSlug/request-access        — request document access
 *   POST   /api/trust/public/:orgSlug/request-questionnaire — request questionnaire
 *
 * Roles: Admin = SUPER_ADMIN | ORG_ADMIN | SECURITY_OWNER
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import crypto from 'crypto';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';

const ADMIN_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];
function isAdmin(user: any) { return ADMIN_ROLES.includes(user?.role); }

// ── Zod schemas ───────────────────────────────────────────────────────────────

const settingsSchema = z.object({
  enabled:      z.boolean().optional(),
  orgSlug:      z.string().min(2).max(60).regex(/^[a-z0-9-]+$/, 'Slug must be lowercase alphanumeric with hyphens').optional(),
  logoUrl:      z.string().url().nullable().optional(),
  primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
  description:  z.string().max(2000).nullable().optional(),
  securityEmail:z.string().email().nullable().optional(),
});

const documentSchema = z.object({
  name:         z.string().min(1),
  category:     z.enum(['POLICY','REPORT','CERTIFICATE','WHITEPAPER','OTHER']),
  fileUrl:      z.string().url(),
  requiresNda:  z.boolean().optional(),
  publicVisible:z.boolean().optional(),
  version:      z.string().nullable().optional(),
});

const announcementSchema = z.object({
  title:     z.string().min(1),
  content:   z.string().min(1),
  type:      z.enum(['SECURITY_UPDATE','INCIDENT','CERTIFICATION','GENERAL']).optional(),
  published: z.boolean().optional(),
});

const accessDecisionSchema = z.object({
  status: z.enum(['APPROVED','REJECTED']),
});

const questionnaireUpdateSchema = z.object({
  status:          z.enum(['PENDING','IN_PROGRESS','COMPLETED']).optional(),
  responseFileUrl: z.string().url().nullable().optional(),
  notes:           z.string().nullable().optional(),
});

// Public schemas
const publicAccessRequestSchema = z.object({
  requesterName:  z.string().min(1),
  requesterEmail: z.string().email(),
  company:        z.string().optional(),
  purpose:        z.string().optional(),
  documentId:     z.string().optional(),
  ndaSigned:      z.boolean().optional(),
});

const publicQuestSchema = z.object({
  requesterEmail:    z.string().email(),
  questionnaireType: z.string().optional(),
});

// ── Helper: compute live compliance snapshot for an org ───────────────────────

async function computeSnapshot(organizationId: string) {
  const controls = await prisma.control.findMany({
    where: { organizationId },
    select: { status: true },
  });
  const total    = controls.length;
  const implemented = controls.filter(c => c.status === 'IMPLEMENTED').length;
  const partial     = controls.filter(c => c.status === 'PARTIALLY_IMPLEMENTED').length;
  const pct = total > 0 ? Math.round(((implemented + partial * 0.5) / total) * 100) : 0;

  // Latest completed audit
  const lastAudit = await prisma.audit.findFirst({
    where: { organizationId, status: 'COMPLETED' },
    orderBy: { closedAt: 'desc' },
    select: { closedAt: true, name: true },
  });

  // Open risks
  const openRisks = await prisma.risk.count({
    where: { asset: { organizationId }, status: 'OPEN' },
  });

  return { total, implemented, partial, pct, lastAudit, openRisks };
}

// ── Route module ──────────────────────────────────────────────────────────────

export async function trustRoutes(app: FastifyInstance) {

  // ─────────────────────────────────────────────────────────────────────────
  // ADMIN: Settings
  // ─────────────────────────────────────────────────────────────────────────

  app.get('/settings', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    let settings = await prisma.trustCenterSettings.findUnique({
      where: { organizationId: user.organizationId },
    });

    // Auto-create with a default slug derived from org id if none exists
    if (!settings) {
      const org = await prisma.organization.findUnique({
        where: { id: user.organizationId },
        select: { name: true },
      });
      const defaultSlug = (org?.name ?? 'org')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '')
        .slice(0, 40) + '-' + user.organizationId.slice(0, 6);

      try {
        settings = await prisma.trustCenterSettings.create({
          data: {
            organizationId: user.organizationId,
            orgSlug: defaultSlug,
          },
        });
      } catch {
        // race condition or slug collision — fetch again
        settings = await prisma.trustCenterSettings.findUnique({
          where: { organizationId: user.organizationId },
        });
      }
    }

    // Attach live compliance snapshot
    const snapshot = await computeSnapshot(user.organizationId);
    return reply.send({ success: true, data: { settings, snapshot } });
  });

  app.put('/settings', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const body = settingsSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    // Ensure slug uniqueness if changing it
    if (body.data.orgSlug) {
      const existing = await prisma.trustCenterSettings.findUnique({ where: { orgSlug: body.data.orgSlug } });
      if (existing && existing.organizationId !== user.organizationId) {
        return reply.status(409).send({ error: 'Slug already taken' });
      }
    }

    const settings = await prisma.trustCenterSettings.upsert({
      where:  { organizationId: user.organizationId },
      create: {
        organizationId: user.organizationId,
        orgSlug: body.data.orgSlug ?? user.organizationId.slice(0, 8),
        ...body.data,
      },
      update: body.data as any,
    });

    return reply.send({ success: true, data: settings });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ADMIN: Documents
  // ─────────────────────────────────────────────────────────────────────────

  app.get('/documents', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const docs = await prisma.trustDocument.findMany({
      where: { organizationId: user.organizationId },
      orderBy: { createdAt: 'desc' },
    });
    return reply.send({ success: true, data: docs });
  });

  app.post('/documents', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const body = documentSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const doc = await prisma.trustDocument.create({
      data: {
        organizationId: user.organizationId,
        uploadedBy:     user.id,
        ...body.data,
      },
    });
    return reply.status(201).send({ success: true, data: doc });
  });

  app.patch('/documents/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });
    const { id } = request.params as { id: string };

    const existing = await prisma.trustDocument.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!existing) return reply.status(404).send({ error: 'Document not found' });

    const body = documentSchema.partial().safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const doc = await prisma.trustDocument.update({ where: { id }, data: body.data as any });
    return reply.send({ success: true, data: doc });
  });

  app.delete('/documents/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });
    const { id } = request.params as { id: string };

    const existing = await prisma.trustDocument.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!existing) return reply.status(404).send({ error: 'Document not found' });

    await prisma.trustDocument.delete({ where: { id } });
    return reply.send({ success: true });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ADMIN: Access Requests
  // ─────────────────────────────────────────────────────────────────────────

  app.get('/access-requests', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const requests = await prisma.trustAccessRequest.findMany({
      where:   { organizationId: user.organizationId },
      include: { document: { select: { id: true, name: true, category: true } } },
      orderBy: { createdAt: 'desc' },
    });
    return reply.send({ success: true, data: requests });
  });

  app.patch('/access-requests/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });
    const { id } = request.params as { id: string };

    const existing = await prisma.trustAccessRequest.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!existing) return reply.status(404).send({ error: 'Request not found' });

    const body = accessDecisionSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const updateData: any = {
      status:     body.data.status,
      approvedBy: user.id,
    };

    if (body.data.status === 'APPROVED') {
      updateData.approvedAt = new Date();
      updateData.approvalToken = crypto.randomBytes(32).toString('hex');
      // Time-limited: 7 days
      updateData.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    }

    const updated = await prisma.trustAccessRequest.update({ where: { id }, data: updateData });
    return reply.send({ success: true, data: updated });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ADMIN: Announcements
  // ─────────────────────────────────────────────────────────────────────────

  app.get('/announcements', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const items = await prisma.trustAnnouncement.findMany({
      where:   { organizationId: user.organizationId },
      orderBy: { createdAt: 'desc' },
    });
    return reply.send({ success: true, data: items });
  });

  app.post('/announcements', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const body = announcementSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const item = await prisma.trustAnnouncement.create({
      data: { organizationId: user.organizationId, ...body.data },
    });
    return reply.status(201).send({ success: true, data: item });
  });

  app.patch('/announcements/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });
    const { id } = request.params as { id: string };

    const existing = await prisma.trustAnnouncement.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!existing) return reply.status(404).send({ error: 'Announcement not found' });

    const body = announcementSchema.partial().safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const item = await prisma.trustAnnouncement.update({ where: { id }, data: body.data as any });
    return reply.send({ success: true, data: item });
  });

  app.delete('/announcements/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });
    const { id } = request.params as { id: string };

    const existing = await prisma.trustAnnouncement.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!existing) return reply.status(404).send({ error: 'Announcement not found' });

    await prisma.trustAnnouncement.delete({ where: { id } });
    return reply.send({ success: true });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ADMIN: Questionnaire Requests
  // ─────────────────────────────────────────────────────────────────────────

  app.get('/questionnaire-requests', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const items = await prisma.trustQuestionnaireRequest.findMany({
      where:   { organizationId: user.organizationId },
      orderBy: { createdAt: 'desc' },
    });
    return reply.send({ success: true, data: items });
  });

  app.patch('/questionnaire-requests/:id', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });
    const { id } = request.params as { id: string };

    const existing = await prisma.trustQuestionnaireRequest.findFirst({
      where: { id, organizationId: user.organizationId },
    });
    if (!existing) return reply.status(404).send({ error: 'Request not found' });

    const body = questionnaireUpdateSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const updateData: any = { ...body.data };
    if (body.data.status === 'COMPLETED') updateData.respondedAt = new Date();

    const item = await prisma.trustQuestionnaireRequest.update({ where: { id }, data: updateData });
    return reply.send({ success: true, data: item });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ADMIN: Metrics Snapshot
  // ─────────────────────────────────────────────────────────────────────────

  app.post('/metrics/snapshot', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Admin only' });

    const snap = await computeSnapshot(user.organizationId);

    const snapshot = await prisma.trustMetricsSnapshot.create({
      data: {
        organizationId:      user.organizationId,
        frameworkName:       'ISO 27001:2022',
        compliancePercentage: snap.pct,
        controlCount:        snap.total,
        completedControls:   snap.implemented,
      },
    });
    return reply.status(201).send({ success: true, data: snapshot });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // PUBLIC: Trust Portal
  // ─────────────────────────────────────────────────────────────────────────

  // GET /api/trust/public/:orgSlug — public portal data (no auth)
  app.get('/public/:orgSlug', async (request: FastifyRequest, reply: FastifyReply) => {
    const { orgSlug } = request.params as { orgSlug: string };

    const settings = await prisma.trustCenterSettings.findUnique({
      where:   { orgSlug },
      include: { organization: { select: { id: true, name: true } } },
    });

    if (!settings || !settings.enabled) {
      return reply.status(404).send({ error: 'Trust center not found or not enabled' });
    }

    const orgId = settings.organizationId;

    // Public documents only
    const documents = await prisma.trustDocument.findMany({
      where:   { organizationId: orgId, publicVisible: true },
      select:  { id: true, name: true, category: true, requiresNda: true, version: true, fileUrl: true },
      orderBy: { createdAt: 'desc' },
    });

    // Published announcements only
    const announcements = await prisma.trustAnnouncement.findMany({
      where:   { organizationId: orgId, published: true },
      select:  { id: true, title: true, content: true, type: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
      take:    10,
    });

    // Latest metrics snapshot
    const metricsSnapshot = await prisma.trustMetricsSnapshot.findFirst({
      where:   { organizationId: orgId },
      orderBy: { snapshotDate: 'desc' },
    });

    // Last completed audit (public info only)
    const lastAudit = await prisma.audit.findFirst({
      where:   { organizationId: orgId, status: 'COMPLETED' },
      orderBy: { closedAt: 'desc' },
      select:  { name: true, type: true, closedAt: true },
    });

    return reply.send({
      success: true,
      data: {
        settings: {
          orgSlug:      settings.orgSlug,
          logoUrl:      settings.logoUrl,
          primaryColor: settings.primaryColor,
          description:  settings.description,
          securityEmail:settings.securityEmail,
          orgName:      (settings as any).organization?.name ?? '',
        },
        documents,
        announcements,
        metricsSnapshot,
        lastAudit,
      },
    });
  });

  // POST /api/trust/public/:orgSlug/request-access — public access request (no auth)
  app.post('/public/:orgSlug/request-access', async (request: FastifyRequest, reply: FastifyReply) => {
    const { orgSlug } = request.params as { orgSlug: string };

    const settings = await prisma.trustCenterSettings.findUnique({ where: { orgSlug } });
    if (!settings || !settings.enabled) return reply.status(404).send({ error: 'Trust center not found' });

    const body = publicAccessRequestSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    // If documentId provided, verify it belongs to this org
    if (body.data.documentId) {
      const doc = await prisma.trustDocument.findFirst({
        where: { id: body.data.documentId, organizationId: settings.organizationId },
      });
      if (!doc) return reply.status(404).send({ error: 'Document not found' });
    }

    const req = await prisma.trustAccessRequest.create({
      data: {
        organizationId: settings.organizationId,
        ...body.data,
      },
    });
    return reply.status(201).send({ success: true, data: { id: req.id } });
  });

  // POST /api/trust/public/:orgSlug/request-questionnaire — public questionnaire request (no auth)
  app.post('/public/:orgSlug/request-questionnaire', async (request: FastifyRequest, reply: FastifyReply) => {
    const { orgSlug } = request.params as { orgSlug: string };

    const settings = await prisma.trustCenterSettings.findUnique({ where: { orgSlug } });
    if (!settings || !settings.enabled) return reply.status(404).send({ error: 'Trust center not found' });

    const body = publicQuestSchema.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });

    const item = await prisma.trustQuestionnaireRequest.create({
      data: {
        organizationId:    settings.organizationId,
        requesterEmail:    body.data.requesterEmail,
        questionnaireType: body.data.questionnaireType ?? 'STANDARD',
      },
    });
    return reply.status(201).send({ success: true, data: { id: item.id } });
  });
}
