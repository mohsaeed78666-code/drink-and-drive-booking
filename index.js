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

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors
      });
    }

    const url = new URL(request.url);

    /*
      Non-API requests are served from the repository assets.
      This allows admin.html and driver.html to be served by the Worker.
    */
    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {

      /* =========================
         DRIVER LOGIN
         ========================= */

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
          driver.password_hash !== await sha256(
            text(body.password)
          )
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


      /* =========================
         DRIVER PROFILE
         ========================= */

      const driver = await getDriver(request, env);

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


      /* =========================
         DRIVER BOOKINGS
         ========================= */

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


      /* =========================
         DRIVER COMPLETES TRIP
         ========================= */

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
          .prepare(
            "SELECT * FROM bookings WHERE booking_number=? AND driver_id=?"
          )
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

        const startKm = Number(body.start_km);
        const endKm = Number(body.end_km);

        const waitingHours = Math.max(
          0,
          Number(body.waiting_hours || 0)
        );

        const waitingMinutes = Math.max(
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

        const distanceKm =
          endKm - startKm;

        /*
          First 10 km are included.
          Beyond 10 km = Rs.100 per km.
        */

        const extraKm =
          Math.max(0, distanceKm - 10);

        const extraKmAmount =
          extraKm * 100;

        /*
          Waiting:
          Rs.500 for every completed
          15-minute block.
        */

        const totalWaitingMinutes =
          waitingHours * 60 +
          waitingMinutes;

        const waitingCharge =
          Math.floor(
            totalWaitingMinutes / 15
          ) * 500;

        const packagePrice =
          Number(
            booking.package_price ??
            booking.price ??
            0
          );

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


      /* =========================
         ADMIN - DRIVER LIST
         ========================= */

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


      /* =========================
         ADMIN - CREATE DRIVER
         ========================= */

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

        const body = await request.json();

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


      /* =========================
         ADMIN - UPDATE DRIVER
         ========================= */

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

        const body = await request.json();

        const fields = [];
        const values = [];

        for (const key of [
          "name",
          "phone",
          "whatsapp",
          "vehicle_number",
          "status",
          "username"
        ]) {
          if (body[key] !== undefined) {
            fields.push(`${key}=?`);
            values.push(text(body[key]));
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
          body.login_enabled !== undefined
        ) {
          fields.push(
            "login_enabled=?"
          );

          values.push(
            body.login_enabled ? 1 : 0
          );
        }

        if (!fields.length) {
          return json(
            { error: "Nothing to update" },
            400
          );
        }

        values.push(
          Number(match[1])
        );

        await env.DB
          .prepare(
            `UPDATE drivers SET ${fields.join(",")} WHERE id=?`
          )
          .bind(...values)
          .run();

        return json({
          ok: true
        });
      }


      /* =========================
         ADMIN - ALL BOOKINGS
         ========================= */

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


      /* =========================
         ADMIN - CREATE BOOKING
         ========================= */

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

        const body = await request.json();

        const packagePrice =
          Number(body.package_price);

        if (
          !text(body.customer_phone) ||
          !text(body.pickup) ||
          !text(body.destination) ||
          !body.booking_date ||
          !body.booking_time ||
          ![
            2500,
            3000,
            3500
          ].includes(packagePrice)
        ) {
          return json({
            error:
              "Required booking details missing"
          }, 400);
        }

        /*
          Booking number is generated
          automatically by the server.
        */

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
            VALUES (
              ?,?,?,?,?,?,?,?,?, 'ASSIGNED',?,CURRENT_TIMESTAMP
            )
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


      /* =========================
         ADMIN - UPDATE BOOKING
         ========================= */

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

        const existing = await env.DB
          .prepare(
            "SELECT id FROM bookings WHERE booking_number=?"
          )
          .bind(bookingNumber)
          .first();
