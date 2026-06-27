import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import { createClient } from "jsr:@supabase/supabase-js@2";
import * as kv from "./kv_store.tsx";

const app = new Hono();

// Middleware
app.use("*", cors());
app.use("*", logger(console.log));

// Initialize admin account on server startup
async function initializeAdmin() {
  try {
    console.log('Checking for admin account...');

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    // Check if admin exists
    const { data: { users }, error: listError } = await supabase.auth.admin.listUsers();

    if (listError) {
      console.log('Error listing users:', listError.message);
      return;
    }

    const adminEmail = 'a206197@siswa.ukm.edu.my';
    const adminExists = users.some(user => user.email === adminEmail);

    if (!adminExists) {
      console.log('Admin not found. Creating admin account...');

      const { data, error } = await supabase.auth.admin.createUser({
        email: adminEmail,
        password: 'Xyd20050801',
        user_metadata: { name: 'Administrator', role: 'admin' },
        email_confirm: true,
      });

      if (error) {
        console.log(`Error creating admin: ${error.message}`);
      } else {
        console.log(`✅ Admin account created successfully: ${adminEmail}`);
        console.log(`   Email: ${adminEmail}`);
        console.log(`   Password: Xyd20050801`);
      }
    } else {
      console.log('✅ Admin account already exists');
    }
  } catch (error) {
    console.log(`Error initializing admin: ${error}`);
  }
}

// Initialize admin on startup
initializeAdmin();


// Health check endpoint
app.get("/make-server-358bdfd0/health", (c) => {
  return c.json({ status: "ok", version: "1.0.1" });
});

// Public endpoint to initialize admin account
app.post("/make-server-358bdfd0/initialize-admin", async (c) => {
  try {
    console.log('Manual admin initialization triggered...');

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    // Check if admin exists
    const { data: { users }, error: listError } = await supabase.auth.admin.listUsers();

    if (listError) {
      console.log('Error listing users:', listError.message);
      return c.json({ error: 'Failed to check users', details: listError.message }, 500);
    }

    const adminEmail = 'a206197@siswa.ukm.edu.my';
    const existingUser = users.find(user => user.email === adminEmail);

    if (existingUser) {
      console.log('✅ Admin already exists');
      return c.json({
        message: 'Admin account already exists',
        email: adminEmail,
        created: false
      });
    }

    // Create admin
    console.log('Creating admin account...');
    const { data, error } = await supabase.auth.admin.createUser({
      email: adminEmail,
      password: 'Xyd20050801',
      user_metadata: { name: 'Administrator', role: 'admin' },
      email_confirm: true,
    });

    if (error) {
      console.log(`Error creating admin: ${error.message}`);
      return c.json({ error: 'Failed to create admin', details: error.message }, 400);
    }

    console.log(`✅ Admin account created successfully: ${adminEmail}`);
    return c.json({
      message: 'Admin account created successfully',
      email: adminEmail,
      created: true
    });
  } catch (error) {
    console.log(`Error in initialize-admin endpoint: ${error}`);
    return c.json({ error: 'Server error', details: String(error) }, 500);
  }
});

// Sign up endpoint
app.post("/make-server-358bdfd0/signup", async (c) => {
  try {
    const { email, password, name } = await c.req.json();
    
    if (!email || !password || !name) {
      return c.json({ error: "Email, password, and name are required" }, 400);
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      user_metadata: { name, role: 'user' },
      // Automatically confirm the user's email since an email server hasn't been configured.
      email_confirm: true
    });

    if (error) {
      console.log(`Sign up error: ${error.message}`);
      return c.json({ error: error.message }, 400);
    }

    return c.json({ 
      message: "User created successfully",
      user: { id: data.user.id, email: data.user.email, name }
    });
  } catch (error) {
    console.log(`Sign up exception: ${error}`);
    return c.json({ error: "Failed to create user" }, 500);
  }
});

// AI Model Detection endpoint
app.post("/make-server-358bdfd0/ai-detect", async (c) => {
  try {
    const { url, apiEndpoint, apiKey } = await c.req.json();

    if (!url) {
      return c.json({ error: "URL is required" }, 400);
    }

    if (!apiEndpoint) {
      return c.json({ error: "AI API endpoint is required" }, 400);
    }

    console.log(`Calling AI model API for URL: ${url}`);
    console.log(`API Endpoint: ${apiEndpoint}`);

    // Validate the endpoint URL before attempting the fetch
    let parsedEndpoint: URL;
    try {
      parsedEndpoint = new URL(apiEndpoint);
    } catch {
      return c.json({
        error: "Invalid API endpoint URL",
        details: "The endpoint must be a valid URL starting with https:// or http://"
      }, 400);
    }

    if (!['https:', 'http:'].includes(parsedEndpoint.protocol)) {
      return c.json({
        error: "Invalid API endpoint URL",
        details: "Only http:// and https:// endpoints are supported"
      }, 400);
    }

    // Call the user's trained AI model
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    let aiResponse: Response;
    try {
      aiResponse = await fetch(apiEndpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({ url }),
      });
    } catch (fetchError) {
      const msg = fetchError instanceof Error ? fetchError.message : String(fetchError);
      console.log(`Network error calling AI API: ${msg}`);
      return c.json({
        error: "Could not reach AI API endpoint",
        details: `Network error: ${msg}. Check that the URL is correct and publicly accessible.`
      }, 502);
    }

    if (!aiResponse.ok) {
      const errorText = await aiResponse.text();
      console.log(`AI API error (${aiResponse.status}): ${errorText}`);
      return c.json({
        error: `AI API returned ${aiResponse.status}`,
        details: errorText,
        status: aiResponse.status
      }, 502);
    }

    const aiResult = await aiResponse.json();
    console.log('AI API response:', aiResult);

    // Return the AI model's prediction
    return c.json({
      success: true,
      url,
      prediction: aiResult,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.log(`Error calling AI model: ${error}`);
    return c.json({
      error: "Failed to call AI model",
      details: error instanceof Error ? error.message : String(error)
    }, 500);
  }
});

// Save detection result endpoint (supports both authenticated and anonymous users)
app.post("/make-server-358bdfd0/detections", async (c) => {
  try {
    console.log('=== Save Detection Request ===');

    const authHeader = c.req.header('Authorization');
    const detectionData = await c.req.json();
    const timestamp = new Date().toISOString();

    console.log('Detection data received:', {
      url: detectionData.url,
      riskScore: detectionData.riskScore,
      isPhishing: detectionData.isPhishing,
      hasAuth: !!authHeader,
      authType: authHeader?.includes('anonymous') ? 'anonymous' : 'authenticated'
    });

    let userId = 'anonymous';
    let userEmail = 'anonymous';

    // Check if user is authenticated
    if (authHeader && !authHeader.includes('anonymous')) {
      const token = authHeader.replace('Bearer ', '');

      const supabase = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      );

      const { data: { user }, error: authError } = await supabase.auth.getUser(token);

      if (!authError && user) {
        userId = user.id;
        userEmail = user.email || 'anonymous';
        console.log('User authenticated:', { userId, userEmail });
      } else {
        console.log('Auth failed, using anonymous:', authError?.message);
      }
    } else {
      console.log('No valid auth header, using anonymous');
    }

    // Generate unique ID for the detection
    const detectionId = `detection:${userId}:${timestamp}:${Math.random().toString(36).substr(2, 9)}`;

    const recordToSave = {
      ...detectionData,
      userId,
      userEmail,
      timestamp,
      id: detectionId
    };

    console.log('Saving to KV store with ID:', detectionId);

    await kv.set(detectionId, recordToSave);

    console.log('✅ Detection saved successfully');

    return c.json({ message: "Detection saved successfully", id: detectionId, saved: true });
  } catch (error) {
    console.log(`❌ Error saving detection: ${error}`);
    console.log(`Error stack: ${error instanceof Error ? error.stack : 'No stack trace'}`);
    return c.json({ error: "Failed to save detection", details: error instanceof Error ? error.message : String(error) }, 500);
  }
});

// Get user's detection history endpoint
app.get("/make-server-358bdfd0/detections", async (c) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Extract token and use service role key to verify
    const token = authHeader.replace('Bearer ', '');

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      console.log(`Auth error while fetching detections: ${authError?.message}`);
      return c.json({ error: "Unauthorized" }, 401);
    }

    const prefix = `detection:${user.id}:`;
    const detections = await kv.getByPrefix(prefix);

    // Sort by timestamp descending (getByPrefix already returns values)
    const sortedDetections = detections
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return c.json({ detections: sortedDetections });
  } catch (error) {
    console.log(`Error fetching detections: ${error}`);
    return c.json({ error: "Failed to fetch detections" }, 500);
  }
});

// Get statistics endpoint
app.get("/make-server-358bdfd0/statistics", async (c) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Extract token and use service role key to verify
    const token = authHeader.replace('Bearer ', '');

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      console.log(`Auth error while fetching statistics: ${authError?.message}`);
      return c.json({ error: "Unauthorized" }, 401);
    }

    const prefix = `detection:${user.id}:`;
    const detections = await kv.getByPrefix(prefix);
    // getByPrefix already returns values
    const detectionValues = detections.filter(v => v != null && v.riskScore != null);

    const totalScans = detectionValues.length;
    const phishingDetected = detectionValues.filter(d => d != null && d.isPhishing).length;
    const safeDetected = totalScans - phishingDetected;
    
    const avgRiskScore = totalScans > 0 
      ? detectionValues.reduce((sum, d) => sum + d.riskScore, 0) / totalScans 
      : 0;

    // Feature analysis
    const featureStats = {
      domainAge: { safe: 0, warning: 0, danger: 0 },
      sslCertificate: { safe: 0, warning: 0, danger: 0 },
      urlLength: { safe: 0, warning: 0, danger: 0 },
      suspiciousKeywords: { safe: 0, warning: 0, danger: 0 },
      domainReputation: { safe: 0, warning: 0, danger: 0 },
      brandSimilarity: { safe: 0, warning: 0, danger: 0 }
    };

    detectionValues.forEach(detection => {
      if (detection && detection.features) {
        Object.entries(detection.features).forEach(([key, feature]: [string, any]) => {
          if (featureStats[key] && feature && feature.status) {
            featureStats[key][feature.status]++;
          }
        });
      }
    });

    // Get recent activity (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentDetections = detectionValues.filter(d =>
      d && d.timestamp && new Date(d.timestamp) >= sevenDaysAgo
    );

    return c.json({
      totalScans,
      phishingDetected,
      safeDetected,
      avgRiskScore: Math.round(avgRiskScore * 10) / 10,
      featureStats,
      recentScans: recentDetections.length,
      phishingRate: totalScans > 0 ? Math.round((phishingDetected / totalScans) * 100) : 0
    });
  } catch (error) {
    console.log(`Error fetching statistics: ${error}`);
    return c.json({ error: "Failed to fetch statistics" }, 500);
  }
});

// Admin: Get all detections with filters
app.get("/make-server-358bdfd0/admin/detections", async (c) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Extract token and use service role key to verify
    const token = authHeader.replace('Bearer ', '');

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      console.log(`Auth error while fetching admin detections: ${authError?.message}`);
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Check if user is admin
    const userRole = user.user_metadata?.role;
    const isAdmin = userRole === 'admin';
    if (!isAdmin) {
      return c.json({ error: "Forbidden - Admin access required" }, 403);
    }

    // Get all detections and filter out null values
    const allDetections = await kv.getByPrefix('detection:');
    // getByPrefix already returns the values directly, not {key, value} objects
    let detectionValues = allDetections.filter(v => v != null && v.riskScore != null);

    // Apply filters from query params
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const riskLevel = c.req.query('riskLevel'); // 'safe', 'suspicious', 'high-risk'
    const domain = c.req.query('domain');
    const userFilter = c.req.query('user');

    if (startDate) {
      detectionValues = detectionValues.filter(d => 
        new Date(d.timestamp) >= new Date(startDate)
      );
    }

    if (endDate) {
      detectionValues = detectionValues.filter(d => 
        new Date(d.timestamp) <= new Date(endDate)
      );
    }

    if (riskLevel) {
      if (riskLevel === 'safe') {
        detectionValues = detectionValues.filter(d => d.riskScore < 30);
      } else if (riskLevel === 'suspicious') {
        detectionValues = detectionValues.filter(d => d.riskScore >= 30 && d.riskScore < 70);
      } else if (riskLevel === 'high-risk') {
        detectionValues = detectionValues.filter(d => d.riskScore >= 70);
      }
    }

    if (domain) {
      detectionValues = detectionValues.filter(d => 
        d.url.toLowerCase().includes(domain.toLowerCase())
      );
    }

    if (userFilter) {
      detectionValues = detectionValues.filter(d => 
        d.userEmail.toLowerCase().includes(userFilter.toLowerCase()) ||
        d.userId === userFilter
      );
    }

    // Sort by timestamp descending
    const sortedDetections = detectionValues.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    return c.json({ 
      detections: sortedDetections,
      total: sortedDetections.length
    });
  } catch (error) {
    console.log(`Error fetching admin detections: ${error}`);
    return c.json({ error: "Failed to fetch detections" }, 500);
  }
});

// Admin: Get global statistics
app.get("/make-server-358bdfd0/admin/statistics", async (c) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader) {
      console.log('No Authorization header provided');
      return c.json({ error: "Unauthorized - No token" }, 401);
    }

    console.log('=== Admin Statistics Request ===');
    console.log('Auth header:', authHeader?.substring(0, 30) + '...');

    // Extract the token from the header
    const token = authHeader.replace('Bearer ', '');

    // Use service role key to verify the token
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    console.log('Verifying user token...');

    // Get user from the token
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    console.log('Auth result:', {
      hasUser: !!user,
      userId: user?.id,
      userEmail: user?.email,
      userRole: user?.user_metadata?.role,
      authError: authError?.message,
    });

    if (authError || !user) {
      console.log(`Auth error while fetching admin statistics: ${authError?.message}`);
      return c.json({ error: "Unauthorized - Invalid token", message: authError?.message || "Invalid JWT" }, 401);
    }

    // Check if user is admin
    const userRole = user.user_metadata?.role;
    const isAdmin = userRole === 'admin';

    console.log('Permission check:', { userRole, isAdmin });

    if (!isAdmin) {
      return c.json({ error: "Forbidden - Admin access required" }, 403);
    }

    // Get all detections and filter out null values
    console.log('Fetching detections from KV store...');
    const allDetections = await kv.getByPrefix('detection:');
    console.log(`Found ${allDetections.length} detection records`);
    console.log('Sample detection:', allDetections[0]);

    // getByPrefix already returns the values directly, not {key, value} objects
    const detectionValues = allDetections.filter(v => v != null && v.riskScore != null);

    console.log(`Filtered to ${detectionValues.length} valid detections`);

    const totalScans = detectionValues.length;
    const phishingDetected = detectionValues.filter(d => d.isPhishing).length;
    const safeDetected = totalScans - phishingDetected;
    
    const avgRiskScore = totalScans > 0 
      ? detectionValues.reduce((sum, d) => sum + d.riskScore, 0) / totalScans 
      : 0;

    // Monthly statistics (last 12 months)
    const monthlyStats: Record<string, { total: number; highRisk: number }> = {};
    const now = new Date();
    for (let i = 0; i < 12; i++) {
      const month = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthKey = month.toISOString().substr(0, 7); // YYYY-MM
      monthlyStats[monthKey] = { total: 0, highRisk: 0 };
    }

    detectionValues.forEach(detection => {
      if (detection.timestamp) {
        const monthKey = detection.timestamp.substr(0, 7);
        if (monthlyStats[monthKey]) {
          monthlyStats[monthKey].total++;
          if (detection.riskScore >= 70) {
            monthlyStats[monthKey].highRisk++;
          }
        }
      }
    });

    // Top abused domains
    const domainCounts: Record<string, number> = {};
    detectionValues.forEach(detection => {
      if (detection.isPhishing) {
        try {
          const url = new URL(detection.url);
          const domain = url.hostname;
          domainCounts[domain] = (domainCounts[domain] || 0) + 1;
        } catch (e) {
          // Invalid URL
          console.log(`Invalid URL in detection: ${detection.url}`);
        }
      }
    });

    const topDomains = Object.entries(domainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([domain, count]) => ({ domain, count }));

    // User statistics
    const uniqueUsers = new Set(detectionValues.map(d => d.userId)).size;
    const anonymousScans = detectionValues.filter(d => d.userId === 'anonymous').length;

    return c.json({
      totalScans,
      phishingDetected,
      safeDetected,
      avgRiskScore: Math.round(avgRiskScore * 10) / 10,
      phishingRate: totalScans > 0 ? Math.round((phishingDetected / totalScans) * 100) : 0,
      uniqueUsers,
      anonymousScans,
      monthlyStats,
      topAbusedDomains: topDomains
    });
  } catch (error) {
    console.log(`Error fetching admin statistics: ${error}`);
    console.log(`Error stack: ${error instanceof Error ? error.stack : 'No stack trace'}`);
    return c.json({
      error: "Failed to fetch statistics",
      details: error instanceof Error ? error.message : String(error)
    }, 500);
  }
});

// Admin: Export cases
app.post("/make-server-358bdfd0/admin/export", async (c) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Extract token and use service role key to verify
    const token = authHeader.replace('Bearer ', '');

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Check if user is admin
    const userRole = user.user_metadata?.role;
    const isAdmin = userRole === 'admin';
    if (!isAdmin) {
      return c.json({ error: "Forbidden - Admin access required" }, 403);
    }

    const { caseIds } = await c.req.json();

    if (!caseIds || !Array.isArray(caseIds)) {
      return c.json({ error: "Invalid case IDs" }, 400);
    }

    // Fetch selected cases
    const cases = await kv.mget(caseIds);
    
    // Anonymize data (remove user identifiers)
    const anonymizedCases = cases.map(caseData => {
      if (!caseData) return null;
      
      const { userId, userEmail, id, ...rest } = caseData;
      return {
        ...rest,
        caseId: id.split(':').pop(), // Only keep the random part
        source: userId === 'anonymous' ? 'Anonymous User' : 'Registered User'
      };
    }).filter(c => c !== null);

    return c.json({ 
      cases: anonymizedCases,
      exportDate: new Date().toISOString(),
      totalCases: anonymizedCases.length
    });
  } catch (error) {
    console.log(`Error exporting cases: ${error}`);
    return c.json({ error: "Failed to export cases" }, 500);
  }
});

Deno.serve(app.fetch);