import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import { createClient } from "jsr:@supabase/supabase-js@2";

const app = new Hono();
const TABLE = "kv_store_358bdfd0";
const ADMIN_EMAIL =
  Deno.env.get("PHISHGUARD_ADMIN_EMAIL") ||
  "a206197@siswa.ukm.edu.my";
const PHISHGUARD_API_URL =
  Deno.env.get("PHISHGUARD_API_URL") ||
  "https://a206197xiatianzephishguard-api.onrender.com/predict";

app.use("*", cors());
app.use("*", logger(console.log));

function serviceClient() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
}

async function authenticatedUser(c: any) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const token = authHeader.slice("Bearer ".length);
  const { data: { user }, error } =
    await serviceClient().auth.getUser(token);
  return error ? null : user;
}

async function adminUser(c: any) {
  const user = await authenticatedUser(c);
  return user?.app_metadata?.role === "admin" ? user : null;
}

async function ensureAdminRole() {
  try {
    const client = serviceClient();
    const { data: { users }, error } =
      await client.auth.admin.listUsers({ page: 1, perPage: 1000 });
    if (error) throw error;

    const admin = users.find(
      (user) => user.email?.toLowerCase() === ADMIN_EMAIL.toLowerCase(),
    );
    if (!admin) {
      console.log(`Admin account ${ADMIN_EMAIL} is not present in Supabase Auth.`);
      return;
    }

    if (admin.app_metadata?.role !== "admin") {
      const { error: updateError } =
        await client.auth.admin.updateUserById(admin.id, {
          app_metadata: { ...admin.app_metadata, role: "admin" },
          user_metadata: {
            ...admin.user_metadata,
            name: admin.user_metadata?.name || "Administrator",
          },
        });
      if (updateError) throw updateError;
    }

    console.log(`Admin authorization configured for ${ADMIN_EMAIL}.`);
  } catch (error) {
    console.log(`Unable to configure admin authorization: ${error}`);
  }
}

async function analyzeUrl(url: string) {
  const response = await fetch(PHISHGUARD_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    throw new Error(`PhishGuard API returned ${response.status}`);
  }

  const result = await response.json();
  if (
    typeof result?.risk_score !== "number" ||
    result.risk_score < 0 ||
    result.risk_score > 100
  ) {
    throw new Error("PhishGuard API returned an invalid risk score");
  }
  return result;
}

async function setValue(key: string, value: any) {
  const { error } = await serviceClient()
    .from(TABLE)
    .upsert({ key, value });
  if (error) throw error;
}

async function valuesByPrefix(prefix: string) {
  const { data, error } = await serviceClient()
    .from(TABLE)
    .select("value")
    .like("key", `${prefix}%`);
  if (error) throw error;
  return (data || []).map((row) => row.value);
}

async function valuesByKeys(keys: string[]) {
  if (keys.length === 0) return [];
  const { data, error } = await serviceClient()
    .from(TABLE)
    .select("value")
    .in("key", keys);
  if (error) throw error;
  return (data || []).map((row) => row.value);
}

function validDetections(values: any[]) {
  return values.filter(
    (value) =>
      value &&
      typeof value.riskScore === "number" &&
      typeof value.timestamp === "string",
  );
}

type RiskBandKey = "trusted" | "lowRisk" | "suspicious" | "highRisk";

type RiskBandCounts = Record<RiskBandKey, number>;

function riskBandForScore(riskScore: number): RiskBandKey {
  if (riskScore < 20) return "trusted";
  if (riskScore < 45) return "lowRisk";
  if (riskScore < 80) return "suspicious";
  return "highRisk";
}

function hasCriticalRule(detection: any) {
  return detection?.critical_phishing === true;
}

function riskBandCounts(detections: any[]): RiskBandCounts {
  const counts: RiskBandCounts = {
    trusted: 0,
    lowRisk: 0,
    suspicious: 0,
    highRisk: 0,
  };

  for (const detection of detections) {
    counts[riskBandForScore(detection.riskScore)] += 1;
  }
  return counts;
}

function highRiskSubmittedHosts(detections: any[]) {
  const byHost: Record<string, {
    host: string;
    count: number;
    mostRecent: any;
    criticalRuleApplications: number;
  }> = {};

  for (const detection of detections) {
    if (detection.riskScore < 80) continue;

    try {
      const host = new URL(detection.url).hostname.toLowerCase();
      if (!host) continue;

      const current = byHost[host] || {
        host,
        count: 0,
        mostRecent: detection,
        criticalRuleApplications: 0,
      };
      current.count += 1;
      if (hasCriticalRule(detection)) current.criticalRuleApplications += 1;
      if (new Date(detection.timestamp).getTime() > new Date(current.mostRecent.timestamp).getTime()) {
        current.mostRecent = detection;
      }
      byHost[host] = current;
    } catch {
      // The dashboard excludes malformed historic URLs from host aggregation.
    }
  }

  return Object.values(byHost)
    .sort((left, right) => right.count - left.count ||
      new Date(right.mostRecent.timestamp).getTime() - new Date(left.mostRecent.timestamp).getTime())
    .slice(0, 10)
    .map((entry) => ({
      host: entry.host,
      detectionCount: entry.count,
      latestSubmittedUrl: entry.mostRecent.url,
      latestRiskScore: entry.mostRecent.riskScore,
      latestCriticalRuleApplied: hasCriticalRule(entry.mostRecent),
      criticalRuleApplications: entry.criticalRuleApplications,
      latestTimestamp: entry.mostRecent.timestamp,
    }));
}

function basicStatistics(values: any[]) {
  const detections = validDetections(values);
  const totalScans = detections.length;
  const phishingDetected =
    detections.filter((item) => item.isPhishing === true).length;
  const avgRiskScore = totalScans
    ? detections.reduce((sum, item) => sum + item.riskScore, 0) / totalScans
    : 0;

  return {
    totalScans,
    phishingDetected,
    safeDetected: totalScans - phishingDetected,
    avgRiskScore: Math.round(avgRiskScore * 10) / 10,
    phishingRate: totalScans
      ? Math.round((phishingDetected / totalScans) * 100)
      : 0,
  };
}

function globalStatistics(values: any[]) {
  const detections = validDetections(values);
  const base = basicStatistics(detections);
  const monthlyStats: Record<string, { total: number; highRisk: number }> = {};
  const now = new Date();

  for (let offset = 0; offset < 12; offset += 1) {
    const month = new Date(now.getFullYear(), now.getMonth() - offset, 1);
    monthlyStats[month.toISOString().slice(0, 7)] = {
      total: 0,
      highRisk: 0,
    };
  }

  for (const detection of detections) {
    const month = detection.timestamp.slice(0, 7);
    if (monthlyStats[month]) {
      monthlyStats[month].total += 1;
      if (detection.riskScore >= 80) monthlyStats[month].highRisk += 1;
    }
  }

  const bands = riskBandCounts(detections);
  const topHosts = highRiskSubmittedHosts(detections);

  return {
    ...base,
    riskBands: bands,
    criticalRuleApplications: detections.filter(hasCriticalRule).length,
    uniqueUsers: new Set(detections.map((item) => item.userId)).size,
    anonymousScans:
      detections.filter((item) => item.userId === "anonymous").length,
    monthlyStats,
    // Kept for existing clients. New admin UI uses the evidence-preserving host records below.
    topAbusedDomains: topHosts.map((entry) => ({
      domain: entry.host,
      count: entry.detectionCount,
    })),
    topHighRiskSubmittedHosts: topHosts,
  };
}

ensureAdminRole();

app.get("/make-server-358bdfd0/health", (c) =>
  c.json({ status: "ok", version: "2.0.0" })
);

app.post("/make-server-358bdfd0/ai-detect", async (c) => {
  try {
    if (!await adminUser(c)) {
      return c.json({ error: "Admin access required" }, 403);
    }

    const body = await c.req.json();
    if (typeof body?.url !== "string" || !body.url.trim()) {
      return c.json({ error: "URL is required" }, 400);
    }

    const prediction = await analyzeUrl(body.url.trim());
    return c.json({
      success: true,
      url: body.url.trim(),
      prediction,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    return c.json({
      error: "Failed to call the PhishGuard API",
      details: error instanceof Error ? error.message : String(error),
    }, 502);
  }
});

app.post("/make-server-358bdfd0/detections", async (c) => {
  try {
    const body = await c.req.json();
    if (typeof body?.url !== "string" || !body.url.trim()) {
      return c.json({ error: "A valid URL is required" }, 400);
    }

    // The server repeats the analysis. Browser-supplied scores are ignored.
    const verified = await analyzeUrl(body.url.trim());
    const user = await authenticatedUser(c);
    const timestamp = new Date().toISOString();
    const userId = user?.id || "anonymous";
    const id =
      `detection:${userId}:${timestamp}:${crypto.randomUUID()}`;
    const record = {
      id,
      url: verified.url || body.url.trim(),
      riskScore: verified.risk_score,
      safetyScore: verified.safety_score,
      isPhishing: verified.prediction === 1,
      result: verified.result,
      decision: verified.decision,
      critical_phishing: verified.critical_phishing,
      explanations: verified.explanations,
      recommendations: verified.recommendations,
      indicators: verified.indicators,
      userId,
      userEmail: user?.email || "anonymous",
      timestamp,
    };

    await setValue(id, record);
    return c.json({ message: "Detection saved", id, saved: true });
  } catch (error) {
    return c.json({
      error: "Failed to save detection",
      details: error instanceof Error ? error.message : String(error),
    }, 500);
  }
});

app.get("/make-server-358bdfd0/detections", async (c) => {
  try {
    const user = await authenticatedUser(c);
    if (!user) return c.json({ error: "Unauthorized" }, 401);

    const detections = validDetections(
      await valuesByPrefix(`detection:${user.id}:`),
    ).sort(
      (left, right) =>
        new Date(right.timestamp).getTime() -
        new Date(left.timestamp).getTime(),
    );
    return c.json({ detections });
  } catch {
    return c.json({ error: "Failed to fetch detections" }, 500);
  }
});

app.get("/make-server-358bdfd0/statistics", async (c) => {
  try {
    const user = await authenticatedUser(c);
    if (!user) return c.json({ error: "Unauthorized" }, 401);

    const detections = await valuesByPrefix(`detection:${user.id}:`);
    return c.json(basicStatistics(detections));
  } catch {
    return c.json({ error: "Failed to fetch statistics" }, 500);
  }
});

app.get("/make-server-358bdfd0/admin/detections", async (c) => {
  try {
    if (!await adminUser(c)) {
      return c.json({ error: "Admin access required" }, 403);
    }

    let detections = validDetections(
      await valuesByPrefix("detection:"),
    );
    const startDate = c.req.query("startDate");
    const endDate = c.req.query("endDate");
    const riskLevel = c.req.query("riskLevel");
    const domain = c.req.query("domain")?.toLowerCase();
    const userFilter = c.req.query("user")?.toLowerCase();

    if (startDate) {
      detections = detections.filter(
        (item) => new Date(item.timestamp) >= new Date(startDate),
      );
    }
    if (endDate) {
      const end = new Date(`${endDate}T23:59:59.999Z`);
      detections = detections.filter(
        (item) => new Date(item.timestamp) <= end,
      );
    }
    if (riskLevel === "trusted") {
      detections = detections.filter((item) => item.riskScore < 20);
    } else if (riskLevel === "low-risk") {
      detections = detections.filter(
        (item) => item.riskScore >= 20 && item.riskScore < 45,
      );
    } else if (riskLevel === "suspicious") {
      detections = detections.filter(
        (item) => item.riskScore >= 45 && item.riskScore < 80,
      );
    } else if (riskLevel === "high-risk") {
      detections = detections.filter((item) => item.riskScore >= 80);
    }

    const criticalRule = c.req.query("criticalRule");
    if (criticalRule === "applied") {
      detections = detections.filter(hasCriticalRule);
    } else if (criticalRule === "not-applied") {
      detections = detections.filter((item) => !hasCriticalRule(item));
    }
    if (domain) {
      detections = detections.filter(
        (item) => String(item.url).toLowerCase().includes(domain),
      );
    }
    if (userFilter) {
      detections = detections.filter(
        (item) =>
          String(item.userEmail).toLowerCase().includes(userFilter) ||
          String(item.userId).toLowerCase() === userFilter,
      );
    }

    detections.sort(
      (left, right) =>
        new Date(right.timestamp).getTime() -
        new Date(left.timestamp).getTime(),
    );
    return c.json({ detections, total: detections.length });
  } catch {
    return c.json({ error: "Failed to fetch detections" }, 500);
  }
});

app.get("/make-server-358bdfd0/admin/statistics", async (c) => {
  try {
    if (!await adminUser(c)) {
      return c.json({ error: "Admin access required" }, 403);
    }
    return c.json(globalStatistics(await valuesByPrefix("detection:")));
  } catch {
    return c.json({ error: "Failed to fetch statistics" }, 500);
  }
});

app.post("/make-server-358bdfd0/admin/export", async (c) => {
  try {
    if (!await adminUser(c)) {
      return c.json({ error: "Admin access required" }, 403);
    }

    const body = await c.req.json();
    if (!Array.isArray(body?.caseIds)) {
      return c.json({ error: "Invalid case IDs" }, 400);
    }

    const cases = (await valuesByKeys(body.caseIds))
      .filter(Boolean)
      .map((caseData) => {
        const { userId, userEmail, id, ...rest } = caseData;
        return {
          ...rest,
          caseId: String(id).split(":").pop(),
          source:
            userId === "anonymous" ? "Anonymous User" : "Registered User",
        };
      });

    return c.json({
      cases,
      exportDate: new Date().toISOString(),
      totalCases: cases.length,
    });
  } catch {
    return c.json({ error: "Failed to export cases" }, 500);
  }
});

Deno.serve(app.fetch);
