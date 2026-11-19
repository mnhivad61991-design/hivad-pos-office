

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS"
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });
}

async function hash(text) {
  const data = new TextEncoder().encode(text);
  const result = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(result)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sign(text, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(text)
  );
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function makeToken(user, secret) {
  const data = btoa(JSON.stringify({
    id: user.id, role: user.role,
    exp: Date.now() + 86400000
  }));
  return data + "." + await sign(data, secret);
}

async function getUser(request, env) {
  const token = request.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  if (await sign(parts[0], env.TOKEN_SECRET) !== parts[1]) return null;
  try {
    const payload = JSON.parse(atob(parts[0]));
    if (payload.exp < Date.now()) return null;
    return await env.DB.prepare(
      "SELECT id,username,name,role FROM users WHERE id=? AND active=1"
    ).bind(payload.id).first();
  } catch { return null; }
}

function allowed(user, roles) {
  return roles.includes(user.role);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS")
      return new Response(null, { headers: cors });

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // ایجاد مدیر اولیه
      if (path === "/api/bootstrap" && method === "POST") {
        const body = await request.json();
        if (body.key !== env.BOOTSTRAP_KEY)
          return response({ error: "کلید اشتباه است" }, 403);

        const exists = await env.DB.prepare(
          "SELECT id FROM users WHERE role='manager' LIMIT 1"
        ).first();
        if (exists) return response({ error: "مدیر قبلاً ساخته شده" }, 409);

        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO users (id,username,name,password_hash,role) VALUES (?,?,?,?,?)"
        ).bind(id, body.username, body.name, await hash(body.password), "manager").run();

        return response({ success: true, message: "مدیر ساخته شد" });
      }

      // ورود
      if (path === "/api/login" && method === "POST") {
        const body = await request.json();
        const user = await env.DB.prepare(
          "SELECT * FROM users WHERE username=? AND active=1"
        ).bind(body.username).first();

        if (!user || user.password_hash !== await hash(body.password))
          return response({ error: "نام کاربری یا رمز اشتباه است" }, 401);

        return response({
          token: await makeToken(user, env.TOKEN_SECRET),
          user: { id: user.id, name: user.name, role: user.role }
        });
      }

      const user = await getUser(request, env);
      if (!user) return response({ error: "ورود لازم است" }, 401);

      if (path === "/api/me")
        return response({ user });

      // فهرست موجودی
      if (path === "/api/inventory" && method === "GET")
        return response(await env.DB.prepare(
          "SELECT * FROM inventory_items ORDER BY id DESC"
        ).all());

      // ثبت کالا در انبار - مدیر
      if (path === "/api/inventory" && method === "POST") {
        if (!allowed(user, ["manager"]))
          return response({ error: "دسترسی غیرمجاز" }, 403);
        const b = await request.json();
        const code = b.code || "I-" + Date.now();
        const result = await env.DB.prepare(
          `INSERT INTO inventory_items
          (code,name,category,model,serial_number,quantity,purchase_price,sale_price,notes)
          VALUES (?,?,?,?,?,?,?,?,?)`
        ).bind(code,b.name,b.category,b.model||null,b.serial_number||null,
          b.quantity||0,b.purchase_price||0,b.sale_price||0,b.notes||null).run();
        return response({ success:true, id:result.meta.last_row_id, code });
      }

      // ثبت پذیرش دستگاه
      if (path === "/api/intakes" && method === "POST") {
        if (!allowed(user, ["manager","employee"]))
          return response({ error: "دسترسی غیرمجاز" }, 403);
        const b = await request.json();
        const code = b.code || "R-" + Date.now();
        const result = await env.DB.prepare(
          `INSERT INTO intakes
          (code,type,device_model,serial_number,customer_name,customer_phone,
          issue,total_amount,paid_amount,payment_status,status,created_by)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
        ).bind(code,b.type,b.device_model||null,b.serial_number||null,
          b.customer_name,b.customer_phone||null,b.issue||null,
          b.total_amount||0,b.paid_amount||0,b.payment_status||"unpaid",
          b.status||"open",user.id).run();

        if (b.type === "repair") {
          await env.DB.prepare(
            "INSERT INTO repair_jobs (intake_id,status) VALUES (?,?)"
          ).bind(result.meta.last_row_id,"pending").run();
        }
        return response({ success:true, code });
      }

      if (path === "/api/intakes" && method === "GET")
        return response(await env.DB.prepare(
          "SELECT * FROM intakes ORDER BY id DESC"
        ).all());

      // پرداخت پذیرش
      if (path.startsWith("/api/intakes/") && path.endsWith("/payment") && method === "POST") {
        if (!allowed(user, ["manager","employee"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const id = path.split("/")[3];
        const b = await request.json();
        await env.DB.prepare(
          "UPDATE intakes SET paid_amount=paid_amount+? WHERE id=?"
        ).bind(b.amount,id).run();
        await env.DB.prepare(
          "INSERT INTO payments (intake_id,amount,method,memo,received_by) VALUES (?,?,?,?,?)"
        ).bind(id,b.amount,b.method,b.memo||null,user.id).run();
        return response({ success:true });
      }

      // ثبت فروش
      if (path === "/api/sales" && method === "POST") {
        if (!allowed(user, ["manager","employee"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const b = await request.json();
        const code = b.code || "S-" + Date.now();
        await env.DB.prepare(
          `INSERT INTO sales
          (code,inventory_id,product_name,quantity,customer_name,customer_phone,
          total_amount,paid_amount,payment_status,status,created_by)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)`
        ).bind(code,b.inventory_id||null,b.product_name,b.quantity||1,
          b.customer_name,b.customer_phone||null,b.total_amount,b.paid_amount||0,
          b.payment_status||"unpaid",b.status||"reserved",user.id).run();
        return response({ success:true,code });
      }

      if (path === "/api/sales" && method === "GET")
        return response(await env.DB.prepare(
          "SELECT * FROM sales ORDER BY id DESC"
        ).all());

      // تحویل فروش
      if (path.startsWith("/api/sales/") && path.endsWith("/deliver") && method === "POST") {
        if (!allowed(user, ["manager","employee"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const id = path.split("/")[3];
        const sale = await env.DB.prepare(
          "SELECT * FROM sales WHERE id=?"
        ).bind(id).first();
        if (!sale) return response({ error:"فروش پیدا نشد" },404);
        if (sale.inventory_id) {
          await env.DB.prepare(
            "UPDATE inventory_items SET quantity=quantity-? WHERE id=? AND quantity>=?"
          ).bind(sale.quantity,sale.inventory_id,sale.quantity).run();
        }
        await env.DB.prepare(
          "UPDATE sales SET status='delivered',delivered_at=CURRENT_TIMESTAMP WHERE id=?"
        ).bind(id).run();
        return response({ success:true });
      }

      // فهرست تعمیرات
      if (path === "/api/repairs" && method === "GET") {
        if (!allowed(user, ["manager","technician"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        return response(await env.DB.prepare(
          `SELECT repair_jobs.*,intakes.code,intakes.customer_name,
          intakes.customer_phone,intakes.device_model,intakes.issue
          FROM repair_jobs JOIN intakes ON repair_jobs.intake_id=intakes.id
          ORDER BY repair_jobs.id DESC`
        ).all());
      }

      // بروزرسانی تعمیر
      if (path.startsWith("/api/repairs/") && method === "PUT") {
        if (!allowed(user, ["manager","technician"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const id = path.split("/")[3];
        const b = await request.json();
        await env.DB.prepare(
          "UPDATE repair_jobs SET status=?,technician_notes=?,labor_fee=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?"
        ).bind(b.status,b.technician_notes||null,b.labor_fee||0,user.id,id).run();
        return response({ success:true });
      }

      // هزینه‌های دفتر
      if (path === "/api/expenses" && method === "POST") {
        if (!allowed(user, ["manager"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const b = await request.json();
        await env.DB.prepare(
          "INSERT INTO expenses (title,amount,details,created_by) VALUES (?,?,?,?)"
        ).bind(b.title,b.amount,b.details||null,user.id).run();
        return response({ success:true });
      }

      // قیمت خدمات
      if (path === "/api/service-prices" && method === "GET")
        return response(await env.DB.prepare(
          "SELECT * FROM service_prices"
        ).all());

      if (path === "/api/service-prices" && method === "POST") {
        if (!allowed(user, ["manager"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const b = await request.json();
        await env.DB.prepare(
          "INSERT OR REPLACE INTO service_prices (service,price,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)"
        ).bind(b.service,b.price).run();
        return response({ success:true });
      }

      // گزارش کلی
      if (path === "/api/report" && method === "GET") {
        if (!allowed(user, ["manager"]))
          return response({ error:"دسترسی غیرمجاز" },403);
        const sales = await env.DB.prepare("SELECT COUNT(*) AS count, SUM(total_amount) AS total FROM sales").first();
        const repairs = await env.DB.prepare("SELECT COUNT(*) AS count FROM repair_jobs").first();
        const expenses = await env.DB.prepare("SELECT SUM(amount) AS total FROM expenses").first();
        return response({ sales, repairs, expenses });
      }

      return response({ error:"مسیر پیدا نشد" },404);
    } catch (e) {
      return response({ error:"خطای سرور", detail:e.message },500);
    }
  }
};
