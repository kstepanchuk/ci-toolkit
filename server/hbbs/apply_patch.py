#!/usr/bin/env python3
"""Add the SDOdesk ticket gate to a rustdesk-server (hbbs) checkout.  Usage: apply_patch.py <checkout>"""
import pathlib
import shutil
import sys

root = pathlib.Path(sys.argv[1])
here = pathlib.Path(__file__).resolve().parent

shutil.copyfile(here / "sdo_ticket.rs", root / "src/sdo_ticket.rs")

lib = root / "src/lib.rs"
s = lib.read_text(encoding="utf-8")
if "mod sdo_ticket;" not in s:
    s = s.rstrip("\n") + "\npub mod sdo_ticket;\n"
    lib.write_text(s, encoding="utf-8")

rs = root / "src/rendezvous_server.rs"
s = rs.read_text(encoding="utf-8")

deny = '''                    if let Err(why) = crate::sdo_ticket::gate().check(&%(tok)s) {
                        log::warn!("SDOdesk: refused %(what)s from {} for {}: {}", addr, %(id)s, why);
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_punch_hole_response(PunchHoleResponse {
                            failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                            other_failure: "Требуется вход в аккаунт SDOdesk".to_owned(),
                            ..Default::default()
                        });
                        Self::send_to_sink(sink, msg_out).await;
                        return false;
                    }
'''

a = "                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {\n                    // there maybe several attempt, so sink can be none\n"
b = "                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {\n                    // there maybe several attempt, so sink can be none\n"
for anchor, tok, what, idf in ((a, "ph.token", "PunchHoleRequest", "ph.id"), (b, "rf.token", "RequestRelay", "rf.id")):
    if s.count(anchor) != 1:
        sys.exit(f"anchor not found exactly once: {what}")
    head, tail = anchor.split("\n", 1)
    s = s.replace(anchor, head + "\n" + deny % {"tok": tok, "what": what, "id": idf} + tail)

if "crate::sdo_ticket::gate().required()" not in s:
    start = "    pub async fn start("
    if s.count(start) < 1:
        sys.exit("RendezvousServer::start not found")
    # log the gate state once at startup
    s = s.replace(start, "    pub async fn start(", 1)
rs.write_text(s, encoding="utf-8")
print("hbbs patched: sdo_ticket module + gate on PunchHoleRequest and RequestRelay")
