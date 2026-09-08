const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key, Authorization",
  "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      ...cors
    }
  });

const text = (value) => String(value ?? "").trim();

async function sha256(value) {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return [...new Uint8Array(buffer)]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}

function isAdmin(request, env) {
  return Boolean(env.ADMIN_KEY) &&
    request.headers.get("X-Admin-Key") === env.ADMIN_KEY;
}

async function getDriver(request, env) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) return null;

  const [id, signature] = header.slice(7).split(".");

  if (!id || !signature) return null;

  const driver = await env.DB
    .prepare(
      "SELECT * FROM drivers WHERE id=? AND login_enabled=1"
    )
    .bind(id)
    .first();

  if (!driver?.password_hash) return null;

  const expected = await sha256(
    `${driver.id}:${driver.password_hash}:${env.SESSION_SECRET || "drink-drive"}`
  );

  return expected === signature ? driver : null;
}

async function driverToken(driver, env) {
  return driver.id + "." + await sha256(
    `${driver.id}:${driver.password_hash}:${env.SESSION_SECRET || "drink-drive"}`
  );
}

/* =========================================================
   PRICING
   Fixed:
   - Included distance: 10 KM
   - Waiting block: 15 minutes

   Editable:
   - Package 1 / Base Price
   - Package 2
   - Package 3
   - Additional KM
   - Waiting charge
========================================================= */

async function ensurePricing(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS pricing_settings (
      id INTEGER PRIMARY KEY CHECK(id=1),
      package1 REAL NOT NULL DEFAULT 2500,
      package2 REAL NOT NULL DEFAULT 3000,
      package3 REAL NOT NULL DEFAULT 3500,
      extra_km_rate REAL NOT NULL DEFAULT 100,
      waiting_block_minutes INTEGER NOT NULL DEFAULT 15,
      waiting_block REAL NOT NULL DEFAULT 500,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO pricing_settings
      (
        id,
        package1,
        package2,
        package3,
        extra_km_rate,
        waiting_block_minutes,
        waiting_block
      )
    VALUES
      (1,2500,3000,3500,100,15,500)
  `).run();
}

async function getPricing(env) {
  await ensurePricing(env);

  const row = await env.DB
    .prepare(
      "SELECT * FROM pricing_settings WHERE id=1"
    )
    .first();

  return {
    packages: [
      Number(row.package1),
      Number(row.package2),
      Number(row.package3)
    ],
    included_km: 10,
    extra_km_rate: Number(row.extra_km_rate),
    waiting_block_minutes: 15,
    waiting_block: Number(row.waiting_block)
  };
}

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors
      });
    }

    const url = new URL(request.url);

    /* =====================================================
       WEBSITE / STATIC FILES
    ===================================================== */

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {

      /* ===================================================
         DRIVER LOGIN
      =================================================== */

      if (
        url.pathname === "/api/driver/login" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const driver = await env.DB
          .prepare(
            "SELECT * FROM drivers WHERE username=? AND login_enabled=1"
          )
          .bind(text(body.username))
          .first();

        if (
          !driver ||
          !driver.password_hash ||
          driver.password_hash !==
            await sha256(text(body.password))
        ) {
          return json(
            { error: "Invalid login" },
            401
          );
        }

        return json({
          token: await driverToken(driver, env),

          driver: {
            id: driver.id,
            name: driver.name,
            phone: driver.phone
          }
        });
      }

      const driver = await getDriver(request, env);

      /* ===================================================
         DRIVER PROFILE
      =================================================== */

      if (
        url.pathname === "/api/driver/me" &&
        request.method === "GET"
      ) {
        if (!driver) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        return json({
          driver: {
            id: driver.id,
            name: driver.name,
            phone: driver.phone
          }
        });
      }

      /* ===================================================
         DRIVER BOOKINGS
      =================================================== */

      if (
        url.pathname === "/api/driver/bookings" &&
        request.method === "GET"
      ) {
        if (!driver) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const result = await env.DB
          .prepare(`
            SELECT *
            FROM bookings
            WHERE driver_id=?
              AND status IN (
                'ASSIGNED',
                'STARTED',
                'COMPLETED',
                'REVIEW'
              )
            ORDER BY booking_date, booking_time
          `)
          .bind(driver.id)
          .all();

        return json({
          bookings: result.results
        });
      }

      /* ===================================================
         DRIVER COMPLETES TRIP
      =================================================== */

      let match = url.pathname.match(
        /^\/api\/driver\/bookings\/([^/]+)\/complete$/
      );

      if (
        match &&
        request.method === "POST"
      ) {
        if (!driver) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const body = await request.json();

        const bookingNumber =
          decodeURIComponent(match[1]);

        const booking = await env.DB
          .prepare(`
            SELECT *
            FROM bookings
            WHERE booking_number=?
              AND driver_id=?
          `)
          .bind(
            bookingNumber,
            driver.id
          )
          .first();

        if (!booking) {
          return json(
            { error: "Booking not found" },
            404
          );
        }

        const startKm =
          Number(body.start_km);

        const endKm =
          Number(body.end_km);

        const waitingHours =
          Math.max(
            0,
            Number(body.waiting_hours || 0)
          );

        const waitingMinutes =
          Math.max(
            0,
            Number(body.waiting_minutes || 0)
          );

        if (
          !Number.isFinite(startKm) ||
          !Number.isFinite(endKm) ||
          endKm < startKm
        ) {
          return json(
            { error: "Invalid KM readings" },
            400
          );
        }

        if (
          !Number.isInteger(waitingHours) ||
          !Number.isInteger(waitingMinutes) ||
          waitingMinutes > 59
        ) {
          return json(
            { error: "Invalid waiting time" },
            400
          );
        }

        /* Get current pricing */

        const pricing =
          await getPricing(env);

        /* Exact distance */

        const distanceKm =
          endKm - startKm;

        /* First 10 KM included */

        const extraKm =
          Math.max(
            0,
            distanceKm - pricing.included_km
          );

        /* Exact extra KM charge */

        const extraKmAmount =
          extraKm *
          pricing.extra_km_rate;

        /* Waiting calculation */

        const totalWaitingMinutes =
          waitingHours * 60 +
          waitingMinutes;

        const completedWaitingBlocks =
          Math.floor(
            totalWaitingMinutes /
            pricing.waiting_block_minutes
          );

        const waitingCharge =
          completedWaitingBlocks *
          pricing.waiting_block;

        /* Package price */

        const packagePrice =
          Number(
            booking.package_price ??
            booking.price ??
            0
          );

        /* Final calculated amount */

        const calculatedAmount =
          packagePrice +
          extraKmAmount +
          waitingCharge;

        await env.DB
          .prepare(`
            UPDATE bookings SET
              start_km=?,
              end_km=?,
              start_meter_photo=?,
              end_meter_photo=?,
              distance_km=?,
              waiting_hours=?,
              waiting_minutes=?,
              extra_km_rate=?,
              extra_km_amount=?,
              waiting_charge=?,
              calculated_amount=?,
              final_amount=?,
              status='COMPLETED',
              completed_at=CURRENT_TIMESTAMP
            WHERE id=?
          `)
          .bind(
            startKm,
            endKm,
            text(body.start_meter_photo),
            text(body.end_meter_photo),
            distanceKm,
            waitingHours,
            waitingMinutes,
            pricing.extra_km_rate,
            extraKmAmount,
            waitingCharge,
            calculatedAmount,
            calculatedAmount,
            booking.id
          )
          .run();

        return json({
          ok: true,
          booking_number: bookingNumber,
          distance_km: distanceKm,
          extra_km_amount: extraKmAmount,
          waiting_charge: waitingCharge,
          calculated_amount: calculatedAmount
        });
      }

      /* ===================================================
         ADMIN DRIVER LIST
      =================================================== */

      if (
        url.pathname === "/api/admin/drivers" &&
        request.method === "GET"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const result = await env.DB
          .prepare(`
            SELECT
              id,
              name,
              phone,
              whatsapp,
              vehicle_number,
              status,
              username,
              login_enabled,
              created_at
            FROM drivers
            ORDER BY name
          `)
          .all();

        return json({
          drivers: result.results
        });
      }

      /* ===================================================
         ADMIN CREATE DRIVER
      =================================================== */

      if (
        url.pathname === "/api/admin/drivers" &&
        request.method === "POST"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const body =
          await request.json();

        if (
          !text(body.name) ||
          !text(body.phone) ||
          !text(body.username) ||
          !text(body.password)
        ) {
          return json({
            error:
              "Name, phone, username and password are required"
          }, 400);
        }

        const passwordHash =
          await sha256(
            text(body.password)
          );

        const result = await env.DB
          .prepare(`
            INSERT INTO drivers
              (
                name,
                phone,
                whatsapp,
                vehicle_number,
                status,
                username,
                password_hash,
                login_enabled
              )
            VALUES (?,?,?,?,?,?,?,1)
          `)
          .bind(
            text(body.name),
            text(body.phone),
            text(body.whatsapp) ||
              text(body.phone),
            text(body.vehicle_number),
            text(body.status) ||
              "available",
            text(body.username),
            passwordHash
          )
          .run();

        return json({
          ok: true,
          id: result.meta.last_row_id
        });
      }

      /* ===================================================
         ADMIN UPDATE DRIVER
      =================================================== */

      match = url.pathname.match(
        /^\/api\/admin\/drivers\/(\d+)$/
      );

      if (
        match &&
        request.method === "PUT"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const body =
          await request.json();

        const fields = [];
        const values = [];

        for (
          const key of [
            "name",
            "phone",
            "whatsapp",
            "vehicle_number",
            "status",
            "username"
          ]
        ) {
          if (
            body[key] !== undefined
          ) {
            fields.push(
              `${key}=?`
            );

            values.push(
              text(body[key])
            );
          }
        }

        if (body.password) {
          fields.push(
            "password_hash=?"
          );

          values.push(
            await sha256(
              text(body.password)
            )
          );
        }

        if (
          body.login_enabled !==
          undefined
        ) {
          fields.push(
            "login_enabled=?"
          );

          values.push(
            body.login_enabled
              ? 1
              : 0
          );
        }

        if (!fields.length) {
          return json({
            error:
              "Nothing to update"
          }, 400);
        }

        values.push(
          Number(match[1])
        );

        await env.DB
          .prepare(`
            UPDATE drivers
            SET ${fields.join(",")}
            WHERE id=?
          `)
          .bind(...values)
          .run();

        return json({
          ok: true
        });
      }

      /* ===================================================
         ADMIN ALL BOOKINGS
      =================================================== */

      if (
        url.pathname === "/api/admin/bookings" &&
        request.method === "GET"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const result = await env.DB
          .prepare(`
            SELECT
              b.*,
              d.name driver_name,
              d.phone driver_phone
            FROM bookings b
            LEFT JOIN drivers d
              ON d.id=b.driver_id
            ORDER BY
              b.booking_date DESC,
              b.booking_time DESC,
              b.id DESC
          `)
          .all();

        return json({
          bookings: result.results
        });
      }

      /* ===================================================
         ADMIN CREATE BOOKING
      =================================================== */

      if (
        url.pathname === "/api/admin/bookings" &&
        request.method === "POST"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const body =
          await request.json();

        const packagePrice =
          Number(body.package_price);

        const pricing =
          await getPricing(env);

        if (
          !text(body.customer_phone) ||
          !text(body.pickup) ||
          !text(body.destination) ||
          !body.booking_date ||
          !body.booking_time ||
          !pricing.packages.includes(
            packagePrice
          )
        ) {
          return json({
            error:
              "Required booking details missing"
          }, 400);
        }

        const bookingNumber =
          "DD-" +
          Date.now()
            .toString(36)
            .toUpperCase();

        await env.DB
          .prepare(`
            INSERT INTO bookings
              (
                customer_name,
                customer_phone,
                pickup,
                destination,
                booking_date,
                booking_time,
                price,
                package_price,
                driver_id,
                status,
                booking_number,
                assigned_at
              )
            VALUES
              (?,?,?,?,?,?,?,?,?,'ASSIGNED',?,CURRENT_TIMESTAMP)
          `)
          .bind(
            text(body.customer_name) ||
              "Customer",
            text(body.customer_phone),
            text(body.pickup),
            text(body.destination),
            body.booking_date,
            body.booking_time,
            packagePrice,
            packagePrice,
            Number(body.driver_id) ||
              null,
            bookingNumber
          )
          .run();

        return json({
          ok: true,
          booking_number:
            bookingNumber
        });
      }

      /* ===================================================
         ADMIN UPDATE BOOKING
      =================================================== */

      match = url.pathname.match(
        /^\/api\/admin\/bookings\/([^/]+)$/
      );

      if (
        match &&
        request.method === "PUT"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const bookingNumber =
          decodeURIComponent(match[1]);

        const existing =
          await env.DB
            .prepare(
              "SELECT id FROM bookings WHERE booking_number=?"
            )
            .bind(bookingNumber)
            .first();

        if (!existing) {
          return json({
            error:
              "Booking not found"
          }, 404);
        }

        const body =
          await request.json();

        const fields = [];
        const values = [];

        if (
          body.driver_id !==
          undefined
        ) {
          fields.push(
            "driver_id=?"
          );

          values.push(
            Number(body.driver_id) ||
              null
          );
        }

        if (
          body.final_amount !==
          undefined
        ) {
          fields.push(
            "final_amount=?"
          );

          values.push(
            Number(body.final_amount)
          );
        }

        if (
          body.status !==
          undefined
        ) {
          fields.push(
            "status=?"
          );

          values.push(
            text(body.status)
          );
        }

        if (
          body.completion_notes !==
          undefined
        ) {
          fields.push(
            "completion_notes=?"
          );

          values.push(
            text(body.completion_notes)
          );
        }

        if (!fields.length) {
          return json({
            error:
              "Nothing to update"
          }, 400);
        }

        values.push(
          existing.id
        );

        await env.DB
          .prepare(`
            UPDATE bookings
            SET ${fields.join(",")}
            WHERE id=?
          `)
          .bind(...values)
          .run();

        return json({
          ok: true
        });
      }

      /* ===================================================
         ADMIN MARK INVOICE SENT
      =================================================== */

      match = url.pathname.match(
        /^\/api\/admin\/bookings\/([^/]+)\/invoice-sent$/
      );

      if (
        match &&
        request.method === "POST"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        await env.DB
          .prepare(`
            UPDATE bookings
            SET
              status='INVOICE_SENT',
              reviewed_at=CURRENT_TIMESTAMP
            WHERE booking_number=?
          `)
          .bind(
            decodeURIComponent(
              match[1]
            )
          )
          .run();

        return json({
          ok: true
        });
      }

      /* ===================================================
         ADMIN GET PRICING
      =================================================== */

      if (
        url.pathname === "/api/admin/pricing" &&
        request.method === "GET"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        return json(
          await getPricing(env)
        );
      }

      /* ===================================================
         ADMIN SAVE PRICING
      =================================================== */

      if (
        url.pathname === "/api/admin/pricing" &&
        request.method === "PUT"
      ) {
        if (!isAdmin(request, env)) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }

        const body =
          await request.json();

        await ensurePricing(env);

        const current =
          await env.DB
            .prepare(
              "SELECT * FROM pricing_settings WHERE id=1"
            )
            .first();

        const package1 =
          Number(
            body.package1 ??
            body.base_price ??
            current.package1
          );

        const package2 =
          Number(
            body.package2 ??
            current.package2
          );

        const package3 =
          Number(
            body.package3 ??
            current.package3
          );

        const extraKmRate =
          Number(
            body.extra_km_rate ??
            current.extra_km_rate
          );

        const waitingBlock =
          Number(
            body.waiting_block ??
            current.waiting_block
          );

        if (
          !Number.isFinite(package1) ||
          package1 < 0 ||

          !Number.isFinite(package2) ||
          package2 < 0 ||

          !Number.isFinite(package3) ||
          package3 < 0 ||

          !Number.isFinite(extraKmRate) ||
          extraKmRate < 0 ||

          !Number.isFinite(waitingBlock) ||
          waitingBlock < 0
        ) {
          return json({
            error:
              "Invalid pricing values"
          }, 400);
        }

        await env.DB
          .prepare(`
            UPDATE pricing_settings
            SET
              package1=?,
              package2=?,
              package3=?,
              extra_km_rate=?,
              waiting_block_minutes=15,
              waiting_block=?,
              updated_at=CURRENT_TIMESTAMP
            WHERE id=1
          `)
          .bind(
            package1,
            package2,
            package3,
            extraKmRate,
            waitingBlock
          )
          .run();

        return json({
          ok: true,
          pricing:
            await getPricing(env)
        });
      }

      /* ===================================================
         UNKNOWN API
      =================================================== */

      return json({
        error: "Not found"
      }, 404);

    } catch (error) {

      return json({
        error:
          error?.message ||
          "Server error"
      }, 500);
    }
  }
};
