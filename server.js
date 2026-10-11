require('dotenv').config();
const path = require('path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createPool } = require('./db/pool');
const { ROLES, roleAllowed, sessionVersionMatches } = require('./authorization');

const app = express();
const pool = createPool();
const PORT = Number(process.env.PORT || 3000);
const ROLE_SET = new Set(ROLES);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32 || /replace-with|change-me|your-secret/i.test(JWT_SECRET)) throw new Error('Set JWT_SECRET to a unique random value of at least 32 characters.');
if (process.env.NODE_ENV === 'production' && process.env.COOKIE_SECURE !== 'true') throw new Error('COOKIE_SECURE=true is required in production.');

app.disable('x-powered-by');
if (process.env.TRUST_PROXY_HOPS) app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use('/api', (req,res,next)=>{
  if (!['POST','PUT','PATCH','DELETE'].includes(req.method) || req.path==='/auth/login' || req.path==='/detections') return next();
  const expected=`${req.protocol}://${req.get('host')}`;
  if (req.get('origin')!==expected) return res.status(403).json({error:'Request origin was rejected.'});
  next();
});
app.use((req, res, next) => {
  if (/^\/(?:server\.js|setup\.js|preview-server\.js|package(?:-lock)?\.json|README\.md|Dockerfile|docker-compose\.ya?ml|\.dockerignore|node_modules(?:\/|$)|db(?:\/|$)|\.env)/i.test(req.path)) return res.status(404).end();
  next();
});
app.use(express.static(__dirname, { index: 'index.html', dotfiles: 'ignore' }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

app.get('/api/config', (req, res) => res.json({ authentication: 'password' }));
app.get('/api/healthz', wrap(async (req, res) => { await pool.query('SELECT 1'); res.json({ status: 'ok' }); }));

function setSession(res, user) {
  const token = jwt.sign({ sub: user.id, role: user.role, sv: Number(user.session_version || 0) }, JWT_SECRET, { expiresIn: '8h', issuer: 'visionon' });
  res.cookie('visionon_session', token, { httpOnly: true, secure: process.env.COOKIE_SECURE === 'true', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000, path: '/' });
}
function auth(req, res, next) {
  const token = req.cookies.visionon_session;
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    const session = jwt.verify(token, JWT_SECRET, { issuer: 'visionon' });
    pool.query('SELECT id, display_name, email, role, active, must_change_password, session_version FROM users WHERE id=$1', [session.sub]).then(({ rows }) => {
      const user = rows[0];
      if (!user || !user.active) return res.status(401).json({ error: 'Account is inactive.' });
      if (!sessionVersionMatches(session.sv, Number(user.session_version))) return res.status(401).json({ error: 'Session expired or revoked.' });
      req.user = user;
      const passwordSetupAllowed=['/api/auth/me','/api/auth/change-password','/api/auth/logout'].includes(req.path);
      if(user.must_change_password&&!passwordSetupAllowed)return res.status(403).json({error:'Set a new password before accessing your portal.',code:'PASSWORD_CHANGE_REQUIRED'});
      next();
    }).catch(next);
  } catch { return res.status(401).json({ error: 'Session expired or invalid.' }); }
}
function allow(...roles) { return (req, res, next) => roleAllowed(req.user.role, roles) ? next() : res.status(403).json({ error: 'This role cannot access this resource.' }); }
async function audit(userId, action, targetId, siteId = null) {
  await pool.query('INSERT INTO audit_events(actor_user_id, action, target_user_id, site_id, created_at) VALUES($1,$2,$3,$4,now())', [userId, action, targetId, siteId]);
}
function wrap(handler) { return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next); }

app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT id, display_name, email, password_hash, role, active, must_change_password, session_version FROM users WHERE lower(email)=$1', [email]);
  const user = rows[0];
  if (!user || !user.active || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  setSession(res, user);
  await audit(user.id, 'sign_in', user.id);
  res.json({ user: { id: user.id, name: user.display_name, email: user.email, role: user.role, mustChangePassword:user.must_change_password } });
}));
app.post('/api/auth/change-password', auth, wrap(async(req,res)=>{
  const password=String(req.body.newPassword||'');
  if(password.length<12||password.length>200||!/[a-z]/.test(password)||!/[A-Z]/.test(password)||!/[0-9]/.test(password))return res.status(400).json({error:'Use 12–200 characters with upper- and lowercase letters and a number.'});
  const user=await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.user.id]);
  if(await bcrypt.compare(password,user.rows[0].password_hash))return res.status(400).json({error:'Choose a password different from your temporary password.'});
  await pool.query('UPDATE users SET password_hash=$1,must_change_password=false WHERE id=$2',[await bcrypt.hash(password,12),req.user.id]);
  await audit(req.user.id,'password_changed',req.user.id);
  res.json({changed:true});
}));
app.post('/api/auth/logout', auth, wrap(async (req, res) => {
  await pool.query('UPDATE users SET session_version=session_version+1 WHERE id=$1', [req.user.id]);
  await audit(req.user.id, 'sign_out', req.user.id);
  res.clearCookie('visionon_session', { httpOnly: true, secure: process.env.COOKIE_SECURE === 'true', sameSite: 'strict', path: '/' });
  res.status(204).end();
}));
app.get('/api/auth/me', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT s.id, s.name FROM sites s JOIN site_memberships m ON m.site_id=s.id WHERE m.user_id=$1 ORDER BY s.name', [req.user.id]);
  res.json({ user: { id: req.user.id, name: req.user.display_name, email: req.user.email, role: req.user.role, mustChangePassword:req.user.must_change_password }, sites: rows });
}));

app.get('/api/sites', auth, wrap(async (req, res) => {
  const query = req.user.role === 'hq' || req.user.role === 'platform_admin'
    ? pool.query('SELECT id, name FROM sites ORDER BY name')
    : pool.query('SELECT s.id, s.name FROM sites s JOIN site_memberships m ON m.site_id=s.id WHERE m.user_id=$1 ORDER BY s.name', [req.user.id]);
  const { rows } = await query;
  res.json({ sites: rows });
}));
app.get('/api/dashboard', auth, wrap(async (req, res) => {
  if (req.user.role === 'platform_admin') return res.status(403).json({ error: 'Operational safety data is not available to platform administrators.' });
  if (req.user.role === 'hq') {
    const { rows } = await pool.query(`SELECT s.id, s.name, count(DISTINCT i.id) FILTER (WHERE i.status IN ('pending','review')) AS active_incidents, count(DISTINCT i.id) AS published_incidents FROM sites s LEFT JOIN incidents i ON i.site_id=s.id LEFT JOIN reports r ON r.incident_id=i.id AND r.status='published' LEFT JOIN report_publications p ON p.report_id=r.id WHERE p.id IS NOT NULL GROUP BY s.id ORDER BY s.name`);
    return res.json({ sites: rows });
  }
  const membership = req.user.role === 'safety_manager' ? 'JOIN site_memberships m ON m.site_id=i.site_id AND m.user_id=$1' : '';
  const where = req.user.role === 'employee' ? 'WHERE i.person_user_id=$1' : '';
  const { rows } = await pool.query(`SELECT count(*) FILTER (WHERE i.status IN ('pending','review')) AS active_incidents, count(*) FILTER (WHERE i.occurred_at >= now()-interval '7 days') AS incidents_week, count(*) FILTER (WHERE i.occurred_at >= now()-interval '24 hours') AS incidents_today FROM incidents i ${membership} ${where}`, req.user.role === 'employee' || req.user.role === 'safety_manager' ? [req.user.id] : []);
  let cameraRows = [{ cameras_online: 0, cameras_total: 0 }];
  if (req.user.role === 'safety_manager') {
    const cameras = await pool.query(`SELECT count(*) FILTER (WHERE c.active AND c.health='operational') AS cameras_online, count(*) FILTER (WHERE c.active) AS cameras_total FROM cameras c JOIN site_memberships m ON m.site_id=c.site_id WHERE m.user_id=$1`, [req.user.id]);
    cameraRows = cameras.rows;
  }
  res.json({ ...rows[0], ...cameraRows[0] });
}));
app.get('/api/cameras', auth, allow('safety_manager'), wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT c.id, c.label, c.health, c.active, c.last_seen_at, s.id AS site_id, s.name AS site_name FROM cameras c JOIN sites s ON s.id=c.site_id JOIN site_memberships m ON m.site_id=s.id AND m.user_id=$1 ORDER BY s.name,c.label`, [req.user.id]);
  res.json({ cameras: rows });
}));
app.get('/api/tasks', auth, allow('employee','safety_manager'), wrap(async (req, res) => {
  const employee = req.user.role === 'employee';
  const { rows } = await pool.query(`SELECT t.id,t.title,t.due_at,t.status,t.completed_at,i.reference,s.name AS site_name FROM tasks t LEFT JOIN incidents i ON i.id=t.incident_id LEFT JOIN sites s ON s.id=COALESCE(t.site_id,i.site_id,(SELECT m.site_id FROM site_memberships m WHERE m.user_id=t.assigned_to ORDER BY m.site_id LIMIT 1)) ${employee ? 'WHERE t.assigned_to=$1' : 'JOIN site_memberships m ON m.site_id=s.id AND m.user_id=$1 WHERE t.status <> $2'} ORDER BY t.due_at NULLS LAST LIMIT 200`, employee ? [req.user.id] : [req.user.id,'complete']);
  res.json({ tasks: rows });
}));
app.get('/api/site/employees', auth, allow('safety_manager'), wrap(async (req,res)=>{
  const {rows}=await pool.query(`SELECT DISTINCT u.id,u.display_name,u.email,s.id AS site_id,s.name AS site_name FROM users u JOIN site_memberships member ON member.user_id=u.id JOIN sites s ON s.id=member.site_id JOIN site_memberships manager ON manager.site_id=s.id AND manager.user_id=$1 WHERE u.role='employee' AND u.active=true ORDER BY s.name,u.display_name`,[req.user.id]);
  res.json({employees:rows});
}));
app.post('/api/tasks', auth, allow('safety_manager'), wrap(async (req,res)=>{
  const {siteId,employeeId,title,dueAt,incidentId}=req.body;
  if(!Number.isInteger(siteId)||!Number.isInteger(employeeId)||typeof title!=='string'||title.trim().length<3||title.length>250)return res.status(400).json({error:'Site, employee, and a task title are required.'});
  const assigned=await pool.query(`SELECT 1 FROM site_memberships manager JOIN site_memberships employee ON employee.site_id=manager.site_id JOIN users u ON u.id=employee.user_id WHERE manager.user_id=$1 AND manager.site_id=$2 AND employee.user_id=$3 AND u.role='employee' AND u.active=true`,[req.user.id,siteId,employeeId]);
  if(!assigned.rowCount)return res.status(403).json({error:'Employee and manager must share this site.'});
  if(incidentId){const incident=await pool.query('SELECT 1 FROM incidents WHERE id=$1 AND site_id=$2',[incidentId,siteId]);if(!incident.rowCount)return res.status(404).json({error:'Incident not found at this site.'})}
  const due=dueAt?new Date(dueAt):null;if(due&&Number.isNaN(due.valueOf()))return res.status(400).json({error:'Invalid due date.'});
  const {rows}=await pool.query('INSERT INTO tasks(site_id,incident_id,assigned_to,title,due_at) VALUES($1,$2,$3,$4,$5) RETURNING id,title,due_at,status',[siteId,incidentId||null,employeeId,title.trim(),due]);
  await audit(req.user.id,'task_assigned',employeeId,siteId);
  res.status(201).json({task:rows[0]});
}));
app.post('/api/tasks/:id/complete', auth, allow('employee'), wrap(async (req, res) => {
  const { rows } = await pool.query(`UPDATE tasks SET status='complete',completed_at=now() WHERE id=$1 AND assigned_to=$2 AND status='open' RETURNING id`, [req.params.id,req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Open task not found.' });
  await audit(req.user.id,'task_completed',req.user.id);
  res.json({ completed: true });
}));

// Each query is scoped on the server. Admin receives only metadata; HQ receives only published, de-identified summaries.
app.get('/api/incidents', auth, wrap(async (req, res) => {
  if (req.user.role === 'platform_admin') return res.status(403).json({ error: 'Incident data is not available to platform administrators.' });
  if (req.user.role === 'employee') {
    const { rows } = await pool.query(`SELECT i.id, i.reference, i.occurred_at, i.event_type, i.severity, i.status, s.name AS site_name, c.label AS camera_label FROM incidents i JOIN sites s ON s.id=i.site_id LEFT JOIN cameras c ON c.id=i.camera_id WHERE i.person_user_id=$1 ORDER BY i.occurred_at DESC LIMIT 200`, [req.user.id]);
    return res.json({ incidents: rows });
  }
  if (req.user.role === 'hq') {
    const { rows } = await pool.query(`SELECT i.id, i.reference, i.occurred_at, i.event_type, i.severity, s.name AS site_name, p.summary, p.recommendation, p.published_at FROM report_publications p JOIN reports r ON r.id=p.report_id JOIN incidents i ON i.id=r.incident_id JOIN sites s ON s.id=i.site_id WHERE p.published_at IS NOT NULL ORDER BY p.published_at DESC LIMIT 200`);
    return res.json({ reports: rows });
  }
  const { rows } = await pool.query(`SELECT i.id, i.reference, i.occurred_at, i.event_type, i.severity, i.status, i.model_confidence, i.reviewed_by, s.name AS site_name, c.label AS camera_label, u.display_name AS person_name FROM incidents i JOIN sites s ON s.id=i.site_id JOIN site_memberships m ON m.site_id=i.site_id AND m.user_id=$1 LEFT JOIN cameras c ON c.id=i.camera_id LEFT JOIN users u ON u.id=i.person_user_id ORDER BY i.occurred_at DESC LIMIT 500`, [req.user.id]);
  res.json({ incidents: rows });
}));

app.post('/api/incidents/:id/review', auth, allow('safety_manager'), wrap(async (req, res) => {
  const { status, note } = req.body;
  if (!['review','resolved','false_positive'].includes(status) || typeof note !== 'string' || note.length > 3000) return res.status(400).json({ error: 'Provide a valid review status and note.' });
  const { rows } = await pool.query(`UPDATE incidents i SET status=$1,reviewed_by=$2,review_note=$3 FROM site_memberships m WHERE i.id=$4 AND m.user_id=$2 AND m.site_id=i.site_id RETURNING i.id,i.reference,i.status`, [status,req.user.id,note.trim()||null,req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Incident not found in your assigned sites.' });
  await audit(req.user.id,'incident_reviewed',null);
  res.json({ incident: rows[0] });
}));
app.post('/api/incidents/:id/acknowledge', auth, allow('employee'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT site_id FROM incidents WHERE id=$1 AND person_user_id=$2', [req.params.id,req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Incident is not linked to your account.' });
  await pool.query('INSERT INTO audit_events(actor_user_id,action,site_id,created_at) VALUES($1,$2,$3,now())', [req.user.id,'incident_acknowledged',rows[0].site_id]);
  res.json({ acknowledged: true });
}));
app.post('/api/detections', rateLimit({windowMs:60*1000,limit:600,standardHeaders:true,legacyHeaders:false}), wrap(async (req, res) => {
  const configured = process.env.DETECTION_API_TOKEN || '';
  const supplied = String(req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!configured || configured.length < 32 || /replace-with|change-me/i.test(configured)) return res.status(503).json({ error: 'Detection ingestion is not configured.' });
  const a=Buffer.from(configured), b=Buffer.from(supplied);
  if (a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({ error: 'Invalid detection service credential.' });
  const { cameraId, eventType, severity, confidence, occurredAt, personUserId, evidenceObjectKey } = req.body;
  if (!Number.isInteger(cameraId) || typeof eventType!=='string' || eventType.length<2 || eventType.length>160 || !['low','medium','high','critical'].includes(severity) || !Number.isFinite(confidence) || confidence<0 || confidence>1) return res.status(400).json({ error: 'Camera, event type, severity, and confidence are required.' });
  const time=occurredAt?new Date(occurredAt):new Date();
  if (Number.isNaN(time.valueOf())) return res.status(400).json({ error: 'Invalid event timestamp.' });
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const camera=await client.query('SELECT id,site_id FROM cameras WHERE id=$1 AND active=true FOR SHARE',[cameraId]);
    if(!camera.rowCount){await client.query('ROLLBACK');return res.status(404).json({error:'Active camera not found.'})}
    if(Number.isInteger(personUserId)){
      const employee=await client.query(`SELECT 1 FROM users u JOIN site_memberships m ON m.user_id=u.id WHERE u.id=$1 AND u.role='employee' AND u.active=true AND m.site_id=$2`,[personUserId,camera.rows[0].site_id]);
      if(!employee.rowCount){await client.query('ROLLBACK');return res.status(400).json({error:'Person identity is not an active employee assigned to this site.'})}
    }
    const reference=`INC-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const result=await client.query(`INSERT INTO incidents(reference,site_id,camera_id,person_user_id,event_type,severity,model_confidence,evidence_object_key,occurred_at,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',now()) RETURNING id,reference,site_id,occurred_at`,[reference,camera.rows[0].site_id,cameraId,Number.isInteger(personUserId)?personUserId:null,eventType,severity,confidence,typeof evidenceObjectKey==='string'?evidenceObjectKey.slice(0,500):null,time]);
    await client.query('UPDATE cameras SET last_seen_at=now() WHERE id=$1',[cameraId]);
    await client.query('COMMIT');
    res.status(201).json({incident:result.rows[0]});
  } catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
}));

app.get('/api/reports', auth, wrap(async (req, res) => {
  if (req.user.role === 'platform_admin' || req.user.role === 'employee') return res.status(403).json({ error: 'Reports are not available for this role.' });
  if (req.user.role === 'hq') {
    const { rows } = await pool.query(`SELECT p.id,p.summary,p.recommendation,p.published_at,r.type,s.name AS site_name,i.reference,i.event_type,i.severity FROM report_publications p JOIN reports r ON r.id=p.report_id JOIN sites s ON s.id=r.site_id LEFT JOIN incidents i ON i.id=r.incident_id WHERE p.published_at IS NOT NULL ORDER BY p.published_at DESC LIMIT 200`);
    return res.json({ reports: rows });
  }
  const { rows } = await pool.query(`SELECT r.id,r.type,r.summary,r.recommendation,r.status,r.created_at,s.name AS site_name,i.reference FROM reports r JOIN sites s ON s.id=r.site_id JOIN site_memberships m ON m.site_id=r.site_id AND m.user_id=$1 LEFT JOIN incidents i ON i.id=r.incident_id ORDER BY r.created_at DESC LIMIT 200`, [req.user.id]);
  res.json({ reports: rows });
}));

app.post('/api/reports', auth, allow('safety_manager'), wrap(async (req, res) => {
  const { siteId, incidentId, type, summary, recommendation } = req.body;
  if (!siteId || !['incident', 'near_miss', 'suggestion', 'corrective_action'].includes(type) || typeof summary !== 'string' || summary.trim().length < 5 || summary.length > 5000) return res.status(400).json({ error: 'Provide a site, report type, and summary between 5 and 5,000 characters.' });
  const membership = await pool.query('SELECT 1 FROM site_memberships WHERE user_id=$1 AND site_id=$2', [req.user.id, siteId]);
  if (!membership.rowCount) return res.status(403).json({ error: 'No access to this site.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (incidentId) {
      const allowed = await client.query('SELECT id FROM incidents WHERE id=$1 AND site_id=$2', [incidentId, siteId]);
      if (!allowed.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Incident not found at this site.' }); }
    }
    const { rows } = await client.query('INSERT INTO reports(site_id, incident_id, author_user_id, type, summary, recommendation, created_at) VALUES($1,$2,$3,$4,$5,$6,now()) RETURNING id, type, created_at', [siteId, incidentId || null, req.user.id, type, summary.trim(), typeof recommendation === 'string' ? recommendation.slice(0, 3000) : null]);
    await client.query('INSERT INTO audit_events(actor_user_id, action, site_id, created_at) VALUES($1,$2,$3,now())', [req.user.id, 'report_created', siteId]);
    await client.query('COMMIT');
    res.status(201).json({ report: rows[0], status: 'manager_review' });
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
}));

app.post('/api/reports/:id/publish', auth, allow('safety_manager'), wrap(async (req, res) => {
  const { siteId, summary, recommendation } = req.body;
  const membership = await pool.query('SELECT 1 FROM site_memberships WHERE user_id=$1 AND site_id=$2', [req.user.id, siteId]);
  if (!membership.rowCount) return res.status(403).json({ error: 'No access to this site.' });
  if (typeof summary !== 'string' || summary.trim().length < 5 || summary.length > 3000) return res.status(400).json({ error: 'Provide a privacy-screened executive summary.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const report = await client.query('SELECT id FROM reports WHERE id=$1 AND site_id=$2 AND status <> $3 FOR UPDATE', [req.params.id, siteId, 'published']);
    if (!report.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Reviewable report not found.' }); }
    const { rows } = await client.query(`INSERT INTO report_publications(report_id, summary, recommendation, published_by, published_at) VALUES($1,$2,$3,$4,now()) RETURNING id, published_at`, [req.params.id, summary.trim(), typeof recommendation === 'string' ? recommendation.slice(0, 2000) : null, req.user.id]);
    await client.query("UPDATE reports SET status='published' WHERE id=$1", [req.params.id]);
    await client.query('INSERT INTO audit_events(actor_user_id, action, site_id, created_at) VALUES($1,$2,$3,now())', [req.user.id, 'report_published', siteId]);
    await client.query('COMMIT');
    res.status(201).json({ publication: rows[0] });
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
}));

app.get('/api/admin/users', auth, allow('platform_admin'), wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT u.id, u.display_name, u.email, u.role, u.active, array_agg(s.name ORDER BY s.name) FILTER (WHERE s.id IS NOT NULL) AS sites FROM users u LEFT JOIN site_memberships m ON m.user_id=u.id LEFT JOIN sites s ON s.id=m.site_id GROUP BY u.id ORDER BY u.display_name`);
  res.json({ users: rows });
}));
app.post('/api/admin/users', auth, allow('platform_admin'), wrap(async (req, res) => {
  const { name, email, role, siteIds } = req.body;
  if (typeof name !== 'string' || name.trim().length < 2 || typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email) || !ROLE_SET.has(role) || !Array.isArray(siteIds)) return res.status(400).json({ error: 'Provide a name, valid email, role, and site IDs.' });
  const temporaryPassword=crypto.randomBytes(18).toString('base64url');
  const hash = await bcrypt.hash(temporaryPassword, 12);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query('INSERT INTO users(display_name,email,password_hash,role,must_change_password) VALUES($1,$2,$3,$4,true) RETURNING id,display_name,email,role', [name.trim(),email.trim().toLowerCase(),hash,role]);
    for (const siteId of [...new Set(siteIds)]) await client.query('INSERT INTO site_memberships(user_id,site_id) VALUES($1,$2)', [rows[0].id,siteId]);
    await client.query('INSERT INTO audit_events(actor_user_id,action,target_user_id,created_at) VALUES($1,$2,$3,now())', [req.user.id,'user_invited',rows[0].id]);
    await client.query('COMMIT');
    res.status(201).json({ user: rows[0], temporaryPassword });
  } catch (err) { await client.query('ROLLBACK'); if (err.code === '23505') return res.status(409).json({ error: 'A user with that email already exists.' }); throw err; } finally { client.release(); }
}));
app.get('/api/admin/audit', auth, allow('platform_admin'), wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT a.action, a.created_at, s.name AS site_name, u.display_name AS actor FROM audit_events a JOIN users u ON u.id=a.actor_user_id LEFT JOIN sites s ON s.id=a.site_id ORDER BY a.created_at DESC LIMIT 500`);
  res.json({ events: rows });
}));
app.put('/api/admin/users/:id/grants', auth, allow('platform_admin'), wrap(async (req, res) => {
  const { role, siteIds, active } = req.body;
  if (!ROLE_SET.has(role) || !Array.isArray(siteIds) || siteIds.some(id => !Number.isInteger(id))) return res.status(400).json({ error: 'A valid role and site ID list are required.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const changed = await client.query('UPDATE users SET role=$1, active=COALESCE($2,active) WHERE id=$3 RETURNING id', [role, typeof active === 'boolean' ? active : null, req.params.id]);
    if (!changed.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'User not found.' }); }
    await client.query('DELETE FROM site_memberships WHERE user_id=$1', [req.params.id]);
    for (const siteId of [...new Set(siteIds)]) await client.query('INSERT INTO site_memberships(user_id,site_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [req.params.id, siteId]);
    await client.query('INSERT INTO audit_events(actor_user_id, action, target_user_id, created_at) VALUES($1,$2,$3,now())', [req.user.id, 'access_grant_updated', req.params.id]);
    await client.query('COMMIT');
    res.json({ updated: true });
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((err, req, res, next) => { console.error('Request failed:', err.message); if (res.headersSent) return next(err); res.status(500).json({ error: 'Request could not be completed.' }); });
const server=app.listen(PORT, () => console.log(`VisionON portal listening on port ${PORT}`));
for (const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>server.close(async()=>{await pool.end();process.exit(0)}));
