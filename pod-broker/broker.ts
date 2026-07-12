// capdel-broker — runs the capdel broker ITSELF as a dstack pod app (attested authority).
// Unlike capdel-relay (a dumb tunnel to a laptop broker), here minting, attenuation and
// enforcement all happen inside the pod, and the audit log lives in the attested
// environment. Secrets arrive via ctx.env — Deno.env may be sandboxed away in the pod —
// so the broker's config is injected, not read at import. Drive the whole protocol over
// HTTP (owner-gated POST /_mint; holders invoke at /caps/<id>/invoke).
//
// capdel.ts here is a symlink to the repo's single source of truth; deploy.sh tars it with
// -h so the real broker source ships in the bundle.
import { configure, ensureHome, handle } from "./capdel.ts";

let ready = false;
export default function (req: Request, ctx: { env: Record<string, string> }): Promise<Response> {
  if (!ready) {
    configure({ CAPDEL_HOME: "/tmp/capdel-state", ...ctx.env });
    ensureHome();
    ready = true;
  }
  return handle(req);
}

// Dev harness: `deno run -A broker.ts` serves the same broker standalone from Deno.env.
if (import.meta.main) {
  const env = Deno.env.toObject();
  configure({ CAPDEL_HOME: env.CAPDEL_HOME ?? "/tmp/capdel-state", ...env });
  ensureHome();
  const port = Number(env.PORT || 8080);
  console.error(`capdel-broker (dev) on http://0.0.0.0:${port}  (owner ${env.CAPDEL_OWNER_SECRET ? "set" : "UNSET"}, pop=${env.CAPDEL_POP || "off"})`);
  Deno.serve({ port, hostname: "0.0.0.0" }, handle);
}
